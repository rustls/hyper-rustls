#![deny(warnings)]
extern crate hyper;
extern crate hyper_rustls;
extern crate env_logger;
extern crate rustls;

use std::io::copy;
use std::fs;
use std::io::BufReader;

use hyper::{Get, Post};
use hyper::server::{Server, Request, Response};
use hyper::uri::RequestUri::AbsolutePath;

macro_rules! try_return(
    ($e:expr) => {{
        match $e {
            Ok(v) => v,
            Err(e) => { println!("Error: {}", e); return; }
        }
    }}
);

fn echo(mut req: Request, mut res: Response) {
    match req.uri {
        AbsolutePath(ref path) => match (&req.method, &path[..]) {
            (&Get, "/") | (&Get, "/echo") => {
                try_return!(res.send(b"Try POST /echo"));
                return;
            },
            (&Post, "/echo") => (), // fall through, fighting mutable borrows
            _ => {
                *res.status_mut() = hyper::NotFound;
                return;
            }
        },
        _ => {
            return;
        }
    };

    let mut res = try_return!(res.start());
    try_return!(copy(&mut req, &mut res));
}

fn load_certs(filename: &str) -> Vec<Vec<u8>> {
    let certfile = fs::File::open(filename)
        .expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader)
      .unwrap()
}

fn load_private_key(filename: &str) -> Vec<u8> {
    let keyfile = fs::File::open(filename)
        .expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let keys = rustls::internal::pemfile::rsa_private_keys(&mut reader)
        .unwrap();
    assert!(keys.len() == 1);
    keys[0].clone()
}

fn main() {
    env_logger::init().unwrap();
    let certs = load_certs("examples/sample.pem");
    let key = load_private_key("examples/sample.rsa");
    let tls = hyper_rustls::TlsServer::new(certs, key);
    let server = Server::https("127.0.0.1:1337", tls).unwrap();
    let _guard = server.handle(echo);
    println!("Listening on https://127.0.0.1:1337");
}
