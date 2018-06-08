use ct_logs;
use futures::{Future, Poll};
use hyper::client::connect::{self, Connect};
use hyper::client::HttpConnector;
use rustls::ClientConfig;
use std::sync::Arc;
use std::{fmt, io};
use tokio_rustls::ClientConfigExt;
use webpki::DNSNameRef;
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
            http: http,
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
    T: Connect<Error=io::Error>,
    T::Transport: 'static,
    T::Future: 'static,
{
    type Transport = MaybeHttpsStream<T::Transport>;
    type Error = io::Error;
    type Future = HttpsConnecting<T::Transport>;

    fn connect(&self, dst: connect::Destination) -> Self::Future {
        let is_https = dst.scheme() == "https";

        if !is_https {
            let connecting = self.http.connect(dst);
            let fut = Box::new(connecting.map(|(tcp, conn)| (MaybeHttpsStream::Http(tcp), conn)));
            HttpsConnecting(fut)
        } else {
            let connecting = self.http.connect(dst.clone());
            let cfg = self.tls_config.clone();
            let fut = Box::new(
                connecting
                    .and_then(move |(tcp, conn)| {
                        let dnsname = DNSNameRef::try_from_ascii_str(dst.host()).unwrap();
                        cfg.connect_async(dnsname, tcp)
                            .and_then(|tls| Ok((MaybeHttpsStream::Https(tls), conn)))
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                    })
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            );
            HttpsConnecting(fut)
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
