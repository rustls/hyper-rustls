#![deny(warnings)]

extern crate futures;
extern crate hyper;
extern crate hyper_rustls;
extern crate rustls;
extern crate tokio_core;

use futures::{Future, Stream};
use hyper::{client, Uri};
use std::str::FromStr;
use std::{env, fs, io};

fn main() {
    // First parameter is target URL (mandatory)
    let url = match env::args().nth(1) {
        Some(ref url) => Uri::from_str(url).expect("well-formed URI"),
        None => {
            println!("Usage: client <url> <ca_store>");
            return;
        }
    };

    // Second parameter is custom Root-CA store (optional, defaults to webpki)
    let mut ca = match env::args().nth(2) {
        Some(ref path) => {
            let f = fs::File::open(path).unwrap();
            let rd = io::BufReader::new(f);
            Some(rd)
        }
        None => None,
    };

    let https = match ca {
        Some(ref mut rd) => {
            let mut http = client::HttpConnector::new(4);
            http.enforce_http(false);
            let mut tls = rustls::ClientConfig::new();
            tls.root_store.add_pem_file(rd).unwrap();
            hyper_rustls::HttpsConnector::from((http, tls))
        }
        None => hyper_rustls::HttpsConnector::new(4),
    };
    let client: client::Client<_, hyper::Body> = client::Client::builder().build(https);

    let fut = client
        .get(url)
        .inspect(|res| {
            println!("Status:\n{}", res.status());
            println!("Headers:\n{:#?}", res.headers());
        })
        .and_then(|res| res.into_body().concat2())
        .inspect(|body| {
            println!("Body:\n{}", String::from_utf8_lossy(&body));
        });

    let mut core = tokio_core::reactor::Core::new().unwrap();
    if let Err(err) = core.run(fut) {
        println!("FAILED: {}", err);
        std::process::exit(1)
    }
}
