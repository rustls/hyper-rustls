use futures_util::FutureExt;
use hyper::client::connect::{self, Connect};
#[cfg(feature = "tokio-runtime")]
use hyper::client::HttpConnector;
use rustls::{ClientConfig, Session};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::{fmt, io};
use tokio_rustls::TlsConnector;
use webpki::DNSNameRef;

use crate::stream::MaybeHttpsStream;

/// A Connector for the `https` scheme.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    tls_config: Arc<ClientConfig>,
}

#[cfg(feature = "tokio-runtime")]
impl HttpsConnector<HttpConnector> {
    /// Construct a new `HttpsConnector`.
    ///
    /// Takes number of DNS worker threads.
    pub fn new() -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let mut config = ClientConfig::new();
        config.root_store = rustls_native_certs::load_native_certs()
            .expect("cannot access native cert store");
        config.ct_logs = Some(&ct_logs::LOGS);
        HttpsConnector {
            http,
            tls_config: Arc::new(config),
        }
    }
}

#[cfg(feature = "tokio-runtime")]
impl Default for HttpsConnector<HttpConnector> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> fmt::Debug for HttpsConnector<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HttpsConnector").finish()
    }
}

impl<T> From<(T, ClientConfig)> for HttpsConnector<T> {
    fn from(args: (T, ClientConfig)) -> Self {
        HttpsConnector {
            http: args.0,
            tls_config: Arc::new(args.1),
        }
    }
}

impl<T> From<(T, Arc<ClientConfig>)> for HttpsConnector<T> {
    fn from(args: (T, Arc<ClientConfig>)) -> Self {
        HttpsConnector {
            http: args.0,
            tls_config: args.1,
        }
    }
}

impl<T> Connect for HttpsConnector<T>
where
    T: Connect<Error = io::Error>,
    T::Transport: 'static,
    T::Future: 'static,
{
    type Transport = MaybeHttpsStream<T::Transport>;
    type Error = io::Error;

    #[allow(clippy::type_complexity)]
    type Future = Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (MaybeHttpsStream<T::Transport>, connect::Connected),
                        io::Error,
                    >,
                > + Send,
        >,
    >;

    fn connect(&self, dst: connect::Destination) -> Self::Future {
        let is_https = dst.scheme() == "https";

        if !is_https {
            let connecting_future = self.http.connect(dst);

            let f = async move {
                let (tcp, conn) = connecting_future.await?;

                Ok((MaybeHttpsStream::Http(tcp), conn))
            };
            f.boxed()
        } else {
            let cfg = self.tls_config.clone();
            let hostname = dst.host().to_string();
            let connecting_future = self.http.connect(dst);

            let f = async move {
                let (tcp, conn) = connecting_future.await?;
                let connector = TlsConnector::from(cfg);
                let dnsname = DNSNameRef::try_from_ascii_str(&hostname)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid dnsname"))?;
                let tls = connector
                    .connect(dnsname, tcp)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let connected = if tls.get_ref().1.get_alpn_protocol() == Some(b"h2") {
                    conn.negotiated_h2()
                } else {
                    conn
                };
                Ok((MaybeHttpsStream::Https(tls), connected))
            };
            f.boxed()
        }
    }
}
