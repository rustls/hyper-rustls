#![deny(warnings)]

extern crate futures;
extern crate hyper;
extern crate hyper_rustls;
extern crate rustls;
extern crate tokio_core;

use futures::{Future, Stream};
use hyper::{client, Uri};
use std::{env, io, fs};
use std::io::Write;
use std::str::FromStr;

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

    let mut core = tokio_core::reactor::Core::new().unwrap();
    let handle = core.handle();
    let https = match ca {
        Some(ref mut rd) => {
            let mut http = client::HttpConnector::new(4, &handle);
            http.enforce_http(false);
            let mut tls = rustls::ClientConfig::new();
            tls.root_store.add_pem_file(rd).unwrap();
            hyper_rustls::HttpsConnector::from((http, tls))
        }
        None => hyper_rustls::HttpsConnector::new(4, &handle),
    };
    let client = client::Client::configure().connector(https).build(&handle);

    let work = client.get(url).and_then(|res| {
        println!("Status: {}", res.status());
        println!("Headers:\n{}", res.headers());
        res.body().for_each(|chunk| {
            ::std::io::stdout().write_all(&chunk).map(|_| ()).map_err(
                From::from,
            )
        })
    });
    if let Err(err) = core.run(work) {
        println!("FAILED: {}", err);
        std::process::exit(1)
    }
}
