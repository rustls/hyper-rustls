#[cfg(feature = "tokio-runtime")]
use hyper::client::connect::HttpConnector;
use hyper::{client::connect::Connection, service::Service, Uri};
use rustls::ClientConfig;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fmt, io};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use webpki::DNSNameRef;

use crate::stream::MaybeHttpsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A Connector for the `https` scheme.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    tls_config: Arc<ClientConfig>,
}

/// A builder that will configure an `HttpsConnector`
///
/// This builder ensures configuration is consistent.
///
/// An alternative way of building an `HttpsConnector`
/// is to use From/Into.
pub struct HttpsConnectorBuilder {
    tls_config: ClientConfig,
}

impl HttpsConnectorBuilder {
    /// Configure using the OS root store for certificate trust
    #[cfg(feature = "rustls-native-certs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls-native-certs")))]
    pub fn with_native_roots() -> Self {
        let mut config = ClientConfig::new();
        config.root_store = match rustls_native_certs::load_native_certs() {
            Ok(store) => store,
            Err((Some(store), err)) => {
                log::warn!("Could not load all certificates: {:?}", err);
                store
            }
            Err((None, err)) => Err(err).expect("cannot access native cert store"),
        };
        if config.root_store.is_empty() {
            panic!("no CA certificates found");
        }
        Self { tls_config: config }
    }

    /// Configure using a custom `rustls::RootCertStore` for certificate trust
    pub fn with_custom_roots(roots: rustls::RootCertStore) -> Self {
        let mut config = ClientConfig::new();
        config.root_store = roots;
        Self { tls_config: config }
    }

    /// Configure using `webpki_roots` for certificate trust
    #[cfg(feature = "webpki-roots")]
    #[cfg_attr(docsrs, doc(cfg(feature = "webpki-roots")))]
    pub fn with_webpki_roots() -> Self {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        Self { tls_config: config }
    }

    /// Enable HTTP2
    /// This advertises http2 support in ALPN
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn enable_http2(mut self) -> Self {
        self.tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        self
    }

    /// Enable certificate transparency
    #[cfg(feature = "ct-logs")]
    pub fn enable_cert_transparency(mut self) -> Self {
        self.tls_config.ct_logs = Some(&ct_logs::LOGS);
        self
    }

    /// Built an HttpsConnector<HttpConnector>
    #[cfg(feature = "tokio-runtime")]
    pub fn build(self) -> HttpsConnector<HttpConnector> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        self.wrap_connector(http)
    }

    /// Built an HttpsConnector with a custom lower-level connector
    pub fn wrap_connector<H>(self, conn: H) -> HttpsConnector<H> {
        (conn, self.tls_config).into()
    }
}

impl<T> fmt::Debug for HttpsConnector<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HttpsConnector").finish()
    }
}

impl<H, C> From<(H, C)> for HttpsConnector<H>
where
    C: Into<Arc<ClientConfig>>,
{
    fn from((http, cfg): (H, C)) -> Self {
        HttpsConnector {
            http,
            tls_config: cfg.into(),
        }
    }
}

impl<T> Service<Uri> for HttpsConnector<T>
where
    T: Service<Uri>,
    T::Response: Connection + AsyncRead + AsyncWrite + Send + Unpin + 'static,
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
        let is_https = dst.scheme_str() == Some("https");

        if !is_https {
            let connecting_future = self.http.call(dst);

            let f = async move {
                let tcp = connecting_future.await.map_err(Into::into)?;

                Ok(MaybeHttpsStream::Http(tcp))
            };
            Box::pin(f)
        } else {
            let cfg = self.tls_config.clone();
            let hostname = dst.host().unwrap_or_default().to_string();
            let connecting_future = self.http.call(dst);

            let f = async move {
                let tcp = connecting_future.await.map_err(Into::into)?;
                let connector = TlsConnector::from(cfg);
                let dnsname = DNSNameRef::try_from_ascii_str(&hostname)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid dnsname"))?;
                let tls = connector
                    .connect(dnsname, tcp)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                Ok(MaybeHttpsStream::Https(tls))
            };
            Box::pin(f)
        }
    }
}
