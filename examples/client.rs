#![deny(warnings)]
extern crate hyper;

extern crate url;
extern crate hyper_rustls;
extern crate env_logger;

use std::env;
use std::io;

use hyper::Client;
use hyper::header::Connection;
use hyper::net::HttpConnector;
use hyper::net::HttpsConnector;
use hyper::client::ProxyConfig;
use url::Url;

fn main() {
    env_logger::init().unwrap();

    let url = match env::args().nth(1) {
        Some(url) => url,
        None => {
            println!("Usage: client <url>");
            return;
        }
    };

    let tls = hyper_rustls::TlsClient::new();

    let client = match env::var("HTTP_PROXY") {
        Ok(proxy) => {
            // parse the proxy, message if it doesn't make sense
            let proxy = match Url::parse(&proxy) {
                Ok(proxy) => proxy,
                Err(why) => panic!("HTTP_PROXY is malformed: {}: {}", proxy, why),
            };

            // connector here gets us to the proxy. tls then is used for https
            // connections via the proxy (tunnelled through the CONNECT method)
            let connector = HttpConnector::default();
            let proxy_config = ProxyConfig::new(
                proxy.scheme(),
                proxy.host_str().unwrap().to_owned(),
                proxy.port().unwrap(),
                connector,
                tls,
            );
            Client::with_proxy_config(proxy_config)
        }
        _ => {
            let connector = HttpsConnector::new(tls);
            Client::with_connector(connector)
        }
    };

    let mut res = client.get(&*url)
        .header(Connection::close())
        .send().unwrap();

    println!("Response: {}", res.status);
    println!("Headers:\n{}", res.headers);
    io::copy(&mut res, &mut io::stdout()).unwrap();
}
