use futures::{Future, Poll};
use hyper::client::HttpConnector;
use hyper::Uri;
use rustls::ClientConfig;
use std::{fmt, io};
use std::sync::Arc;
use stream::MaybeHttpsStream;
use tokio_core::reactor::Handle;
use tokio_rustls::ClientConfigExt;
use tokio_service::Service;
use webpki_roots;

#[derive(Clone)]
pub struct HttpsConnector {
    http: HttpConnector,
    tls_config: Arc<ClientConfig>,
}

impl HttpsConnector {
    /// Construct a new HttpsConnector.
    ///
    /// Takes number of DNS worker threads.
    pub fn new(threads: usize, handle: &Handle) -> HttpsConnector {
        let mut http = HttpConnector::new(threads, handle);
        http.enforce_http(false);
        let mut config = ClientConfig::new();
        config.root_store.add_trust_anchors(&webpki_roots::ROOTS);
        HttpsConnector { http: http, tls_config: Arc::new(config) }
    }
}

impl fmt::Debug for HttpsConnector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HttpsConnector").finish()
    }
}

impl From<(HttpConnector, ClientConfig)> for HttpsConnector {
    fn from(args: (HttpConnector, ClientConfig)) -> HttpsConnector {
        HttpsConnector {
            http: args.0,
            tls_config: Arc::new(args.1),
        }
    }
}

impl Service for HttpsConnector {
    type Request = Uri;
    type Response = MaybeHttpsStream;
    type Error = io::Error;
    type Future = HttpsConnecting;

    fn call(&self, uri: Uri) -> Self::Future {
        let is_https = uri.scheme() == Some("https");
        let host = match uri.host() {
            Some(host) => host.to_owned(),
            None => return HttpsConnecting(
                Box::new(
                    ::futures::future::err(
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "invalid url, missing host"
                            )
                        )
                    )
                ),
        };
        let connecting = self.http.call(uri);

        HttpsConnecting(if is_https {
            let tls = self.tls_config.clone();
            Box::new(connecting.and_then(move |tcp| {
                    tls
                    .connect_async(&host, tcp)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            }).map(|tls| MaybeHttpsStream::Https(tls))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)))
        } else {
            Box::new(connecting.map(|tcp| MaybeHttpsStream::Http(tcp)))
        })
    }
}


pub struct HttpsConnecting(Box<Future<Item = MaybeHttpsStream, Error = io::Error>>);

impl Future for HttpsConnecting {
    type Item = MaybeHttpsStream;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl fmt::Debug for HttpsConnecting {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("HttpsConnecting")
    }
}
