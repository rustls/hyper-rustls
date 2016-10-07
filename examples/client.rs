#![deny(warnings)]
extern crate hyper;

extern crate hyper_rustls;

extern crate env_logger;

use std::env;
use std::io;

use hyper::Client;
use hyper::header::Connection;
use hyper::net::HttpsConnector;

fn main() {
    env_logger::init().unwrap();

    let url = match env::args().nth(1) {
        Some(url) => url,
        None => {
            println!("Usage: client <url>");
            return;
        }
    };

    let client = Client::with_connector(HttpsConnector::new(hyper_rustls::TlsClient::new()));

    let mut res = client.get(&*url)
        .header(Connection::close())
        .send().unwrap();

    println!("Response: {}", res.status);
    println!("Headers:\n{}", res.headers);
    io::copy(&mut res, &mut io::stdout()).unwrap();
}
