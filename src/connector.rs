use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fmt, io};

use http::Uri;
use hyper::rt;
use hyper_util::client::legacy::connect::Connection;
use hyper_util::rt::TokioIo;
use pki_types::ServerName;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use crate::stream::MaybeHttpsStream;

pub(crate) mod builder;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A Connector for the `https` scheme.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    force_https: bool,
    http: T,
    tls_config: Arc<rustls::ClientConfig>,
    server_name_resolver: Arc<dyn ResolveServerName + Sync + Send>,
}

impl<T> HttpsConnector<T> {
    /// Creates a [`crate::HttpsConnectorBuilder`] to configure a `HttpsConnector`.
    ///
    /// This is the same as [`crate::HttpsConnectorBuilder::new()`].
    pub fn builder() -> builder::ConnectorBuilder<builder::WantsTlsConfig> {
        builder::ConnectorBuilder::new()
    }

    /// Force the use of HTTPS when connecting.
    ///
    /// If a URL is not `https` when connecting, an error is returned.
    pub fn enforce_https(&mut self) {
        self.force_https = true;
    }
}

impl<T> Service<Uri> for HttpsConnector<T>
where
    T: Service<Uri>,
    T::Response: Connection + rt::Read + rt::Write + Send + Unpin + 'static,
    T::Future: Send + 'static,
    T::Error: Into<BoxError>,
{
    type Response = MaybeHttpsStream<T::Response>;
    type Error = BoxError;

    #[allow(clippy::type_complexity)]
    type Future =
        Pin<Box<dyn Future<Output = Result<MaybeHttpsStream<T::Response>, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.http.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        // dst.scheme() would need to derive Eq to be matchable;
        // use an if cascade instead
        match dst.scheme() {
            Some(scheme) if scheme == &http::uri::Scheme::HTTP && !self.force_https => {
                let future = self.http.call(dst);
                return Box::pin(async move {
                    Ok(MaybeHttpsStream::Http(future.await.map_err(Into::into)?))
                });
            }
            Some(scheme) if scheme != &http::uri::Scheme::HTTPS => {
                let message = format!("unsupported scheme {scheme}");
                return Box::pin(async move {
                    Err(io::Error::new(io::ErrorKind::Other, message).into())
                });
            }
            Some(_) => {}
            None => {
                return Box::pin(async move {
                    Err(io::Error::new(io::ErrorKind::Other, "missing scheme").into())
                })
            }
        };

        let cfg = self.tls_config.clone();
        let hostname = match self.server_name_resolver.resolve(&dst) {
            Ok(hostname) => hostname,
            Err(e) => {
                return Box::pin(async move { Err(e) });
            }
        };

        let connecting_future = self.http.call(dst);
        Box::pin(async move {
            let tcp = connecting_future
                .await
                .map_err(Into::into)?;
            Ok(MaybeHttpsStream::Https(TokioIo::new(
                TlsConnector::from(cfg)
                    .connect(hostname, TokioIo::new(tcp))
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
            )))
        })
    }
}

impl<H, C> From<(H, C)> for HttpsConnector<H>
where
    C: Into<Arc<rustls::ClientConfig>>,
{
    fn from((http, cfg): (H, C)) -> Self {
        Self {
            force_https: false,
            http,
            tls_config: cfg.into(),
            server_name_resolver: Arc::new(DefaultServerNameResolver::default()),
        }
    }
}

impl<T> fmt::Debug for HttpsConnector<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HttpsConnector")
            .field("force_https", &self.force_https)
            .finish()
    }
}

/// The default server name resolver, which uses the hostname in the URI.
#[derive(Default)]
pub struct DefaultServerNameResolver(());

impl ResolveServerName for DefaultServerNameResolver {
    fn resolve(
        &self,
        uri: &Uri,
    ) -> Result<ServerName<'static>, Box<dyn std::error::Error + Sync + Send>> {
        let mut hostname = uri.host().unwrap_or_default();

        // Remove square brackets around IPv6 address.
        if let Some(trimmed) = hostname
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
        {
            hostname = trimmed;
        }

        ServerName::try_from(hostname.to_string()).map_err(|e| Box::new(e) as _)
    }
}

/// A server name resolver which always returns the same fixed name.
pub struct FixedServerNameResolver {
    name: ServerName<'static>,
}

impl FixedServerNameResolver {
    /// Creates a new resolver returning the specified name.
    pub fn new(name: ServerName<'static>) -> Self {
        Self { name }
    }
}

impl ResolveServerName for FixedServerNameResolver {
    fn resolve(
        &self,
        _: &Uri,
    ) -> Result<ServerName<'static>, Box<dyn std::error::Error + Sync + Send>> {
        Ok(self.name.clone())
    }
}

impl<F, E> ResolveServerName for F
where
    F: Fn(&Uri) -> Result<ServerName<'static>, E>,
    E: Into<Box<dyn std::error::Error + Sync + Send>>,
{
    fn resolve(
        &self,
        uri: &Uri,
    ) -> Result<ServerName<'static>, Box<dyn std::error::Error + Sync + Send>> {
        self(uri).map_err(Into::into)
    }
}

/// A trait implemented by types that can resolve a [`ServerName`] for a request.
pub trait ResolveServerName {
    /// Maps a [`Uri`] into a [`ServerName`].
    fn resolve(
        &self,
        uri: &Uri,
    ) -> Result<ServerName<'static>, Box<dyn std::error::Error + Sync + Send>>;
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs"),
    any(
        feature = "rustls-native-certs",
        feature = "webpki-roots",
        feature = "rustls-platform-verifier",
    )
))]
mod tests {
    use std::future::poll_fn;

    use http::Uri;
    use hyper_util::client::legacy::connect::HttpConnector;
    use tower_service::Service;

    use super::HttpsConnector;
    use crate::{ConfigBuilderExt, HttpsConnectorBuilder};

    fn tls_config() -> rustls::ClientConfig {
        #[cfg(feature = "rustls-native-certs")]
        return rustls::ClientConfig::builder()
            .with_native_roots()
            .unwrap()
            .with_no_client_auth();

        #[cfg(feature = "webpki-roots")]
        return rustls::ClientConfig::builder()
            .with_webpki_roots()
            .with_no_client_auth();

        #[cfg(feature = "rustls-platform-verifier")]
        return rustls::ClientConfig::builder()
            .with_platform_verifier()
            .with_no_client_auth();
    }

    fn https_or_http_connector() -> HttpsConnector<HttpConnector> {
        HttpsConnectorBuilder::new()
            .with_tls_config(tls_config())
            .https_or_http()
            .enable_http1()
            .build()
    }

    fn https_only_connector() -> HttpsConnector<HttpConnector> {
        HttpsConnectorBuilder::new()
            .with_tls_config(tls_config())
            .https_only()
            .enable_http1()
            .build()
    }

    async fn oneshot<S, Req>(mut service: S, req: Req) -> Result<S::Response, S::Error>
    where
        S: Service<Req>,
    {
        poll_fn(|cx| service.poll_ready(cx)).await?;
        service.call(req).await
    }

    fn https_uri() -> Uri {
        Uri::from_static("https://google.com")
    }

    fn http_uri() -> Uri {
        Uri::from_static("http://google.com")
    }

    #[tokio::test]
    async fn connects_https() {
        oneshot(https_or_http_connector(), https_uri())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn connects_http() {
        oneshot(https_or_http_connector(), http_uri())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn connects_https_only() {
        oneshot(https_only_connector(), https_uri())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn enforces_https_only() {
        let message = oneshot(https_only_connector(), http_uri())
            .await
            .unwrap_err()
            .to_string();

        assert_eq!(message, "unsupported scheme http");
    }
}
