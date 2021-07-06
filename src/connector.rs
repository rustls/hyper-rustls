use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fmt, io};
use std::convert::TryFrom;

#[cfg(feature = "tokio-runtime")]
use hyper::client::connect::HttpConnector;
use hyper::{client::connect::Connection, service::Service, Uri};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

use crate::stream::MaybeHttpsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A Connector for the `https` scheme.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    tls_config: Arc<ClientConfig>,
}

#[cfg(all(
    any(feature = "rustls-native-certs", feature = "webpki-roots"),
    feature = "tokio-runtime"
))]
impl HttpsConnector<HttpConnector> {
    /// Construct a new `HttpsConnector` using the OS root store
    #[cfg(feature = "rustls-native-certs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls-native-certs")))]
    pub fn with_native_roots() -> Self {
        let certs = match rustls_native_certs::load_native_certs() {
            Ok(certs) => certs,
            Err(err) => Err(err).expect("cannot access native cert store"),
        };

        if certs.is_empty() {
            panic!("no CA certificates found");
        }

        let mut roots = RootCertStore::empty();
        for cert in certs {
            roots.add_parsable_certificates(&[cert.0]);
        }

        Self::build(roots)
    }

    /// Construct a new `HttpsConnector` using the `webpki_roots`
    #[cfg(feature = "webpki-roots")]
    #[cfg_attr(docsrs, doc(cfg(feature = "webpki-roots")))]
    pub fn with_webpki_roots() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0);
        Self::build(roots)
    }

    fn build(roots: rustls::RootCertStore) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots, &ct_logs::LOGS)
            .with_no_client_auth();

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        (http, config).into()
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
                let dnsname = rustls::ServerName::try_from(hostname.as_str())
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
