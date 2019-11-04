use futures::{Future, Poll};
use hyper::client::connect::{self, Connect};
#[cfg(feature = "tokio-runtime")]
use hyper::client::HttpConnector;
use rustls::{ClientConfig, Session};
use std::sync::Arc;
use std::{fmt, io};
use tokio_rustls::TlsConnector;
use webpki::{DNSName, DNSNameRef};

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
    pub fn new(threads: usize) -> Self {
        let mut http = HttpConnector::new(threads);
        http.enforce_http(false);
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.ct_logs = Some(&ct_logs::LOGS);
        HttpsConnector {
            http,
            tls_config: Arc::new(config),
        }
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
    type Future = HttpsConnecting<T::Transport>;

    fn connect(&self, dst: connect::Destination) -> Self::Future {
        let is_https = dst.scheme() == "https";
        let hostname = dst.host().to_string();
        let connecting = self.http.connect(dst);

        if !is_https {
            let fut = connecting.map(|(tcp, conn)| (MaybeHttpsStream::Http(tcp), conn));
            HttpsConnecting(Box::new(fut))
        } else {
            let cfg = self.tls_config.clone();
            let connector = TlsConnector::from(cfg);
            let fut = connecting
                .map(move |(tcp, conn)| (tcp, conn, hostname))
                .and_then(
                    |(tcp, conn, hostname)| match DNSNameRef::try_from_ascii_str(&hostname) {
                        Ok(dnsname) => Ok((tcp, conn, DNSName::from(dnsname))),
                        Err(_) => Err(io::Error::new(io::ErrorKind::Other, "invalid dnsname")),
                    },
                )
                .and_then(move |(tcp, conn, dnsname)| {
                    connector
                        .connect(dnsname.as_ref(), tcp)
                        .and_then(|tls| {
                            let connected = if tls.get_ref().1.get_alpn_protocol() == Some(b"h2") {
                                conn.negotiated_h2()
                            } else {
                                conn
                            };
                            Ok((MaybeHttpsStream::Https(tls), connected))
                        })
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                });
            HttpsConnecting(Box::new(fut))
        }
    }
}

/// A Future representing work to connect to a URL, and a TLS handshake.
pub struct HttpsConnecting<T>(
    Box<dyn Future<Item = (MaybeHttpsStream<T>, connect::Connected), Error = io::Error> + Send>,
);

impl<T> Future for HttpsConnecting<T> {
    type Item = (MaybeHttpsStream<T>, connect::Connected);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl<T> fmt::Debug for HttpsConnecting<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("HttpsConnecting")
    }
}
