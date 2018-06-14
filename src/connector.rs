use ct_logs;
use futures::{Future, Poll};
use hyper::client::connect::{self, Connect};
use hyper::client::HttpConnector;
use rustls::ClientConfig;
use std::sync::Arc;
use std::{fmt, io};
use tokio_rustls::ClientConfigExt;
use webpki::{DNSName, DNSNameRef};
use webpki_roots;

use stream::MaybeHttpsStream;

/// A Connector for the `https` scheme.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    tls_config: Arc<ClientConfig>,
}

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
            let fut = connecting
                .map(move |(tcp, conn)| (tcp, conn, hostname))
                .and_then(
                    |(tcp, conn, hostname)| match DNSNameRef::try_from_ascii_str(&hostname) {
                        Ok(dnsname) => Ok((tcp, conn, DNSName::from(dnsname))),
                        Err(_) => Err(io::Error::new(io::ErrorKind::Other, "invalid dnsname")),
                    },
                )
                .and_then(move |(tcp, conn, dnsname)| {
                    cfg.connect_async(dnsname.as_ref(), tcp)
                        .and_then(|tls| Ok((MaybeHttpsStream::Https(tls), conn)))
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                });
            HttpsConnecting(Box::new(fut))
        }
    }
}

/// A Future representing work to connect to a URL, and a TLS handshake.
pub struct HttpsConnecting<T>(
    Box<Future<Item = (MaybeHttpsStream<T>, connect::Connected), Error = io::Error> + Send>,
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
