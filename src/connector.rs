use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fmt, io};

use hyper::client::connect::Connection;
use hyper::service::Service;
use hyper::Uri;
use pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

use crate::stream::MaybeHttpsStream;

pub(crate) mod builder;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A Connector for the `https` scheme.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    force_https: bool,
    http: T,
    tls_config: Arc<rustls::ClientConfig>,
    override_server_name: Option<String>,
}

impl<T> HttpsConnector<T> {
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
        // dst.scheme() would need to derive Eq to be matchable;
        // use an if cascade instead
        match dst.scheme() {
            Some(scheme) if scheme == &http::uri::Scheme::HTTP => {
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
        let mut hostname = match self.override_server_name.as_deref() {
            Some(h) => h,
            None => dst.host().unwrap_or_default(),
        };

        // Remove square brackets around IPv6 address.
        if let Some(trimmed) = hostname
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
        {
            hostname = trimmed;
        }

        let hostname = match ServerName::try_from(hostname) {
            Ok(dns_name) => dns_name.to_owned(),
            Err(_) => {
                let err = io::Error::new(io::ErrorKind::Other, "invalid dnsname");
                return Box::pin(async move { Err(Box::new(err).into()) });
            }
        };

        let connecting_future = self.http.call(dst);
        Box::pin(async move {
            let tcp = connecting_future
                .await
                .map_err(Into::into)?;
            Ok(MaybeHttpsStream::Https(
                TlsConnector::from(cfg)
                    .connect(hostname, tcp)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
            ))
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
            override_server_name: None,
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
