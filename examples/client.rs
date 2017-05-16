#![deny(warnings)]

extern crate futures;
extern crate hyper;
extern crate hyper_rustls;
extern crate tokio_core;

use futures::future::Future;
use futures::Stream;
use hyper::Uri;
use std::env;
use std::io::Write;
use std::str::FromStr;

fn main() {
    let url = match env::args().nth(1) {
        Some(url) => Uri::from_str(&*url).expect("well-formed URI"),
        None => {
            println!("Usage: client <url>");
            return;
        }
    };

    let mut core = tokio_core::reactor::Core::new().unwrap();
    let handle = core.handle();
    let client = hyper::Client::configure()
                .connector(hyper_rustls::HttpsConnector::new(4, &handle))
                .build(&handle);


    let work = client.get(url).and_then(|res| {
        println!("Status: {}", res.status());
        println!("Headers:\n{}", res.headers());
        res.body().for_each(|chunk| {
            ::std::io::stdout().write_all(&chunk)
                .map(|_| ())
                .map_err(From::from)
        })
    });
    if let Err(err) =  core.run(work) {
        println!("FAILED: {}", err);
    }
}
