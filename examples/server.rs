#![deny(warnings)]

extern crate futures;
extern crate hyper;
extern crate rustls;
extern crate tokio_proto;
extern crate tokio_rustls;

use futures::future::FutureResult;
use hyper::header::ContentLength;
use hyper::server::{Http, Service, Request, Response};
use hyper::{Get, Post, StatusCode};
use tokio_rustls::proto;
use rustls::internal::pemfile;

static INDEX: &'static [u8] = b"Try POST /echo\n";

#[derive(Clone, Copy)]
struct Echo;

impl Service for Echo {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = FutureResult<Response, hyper::Error>;

    fn call(&self, req: Request) -> Self::Future {
        futures::future::ok(match (req.method(), req.path()) {
                                (&Get, "/") | (&Get, "/echo") => {
                                    Response::new()
                                        .with_header(ContentLength(INDEX.len() as u64))
                                        .with_body(INDEX)
                                }
                                (&Post, "/echo") => {
                                    let mut res = Response::new();
                                    if let Some(len) = req.headers().get::<ContentLength>() {
                                        res.headers_mut().set(len.clone());
                                    }
                                    res.with_body(req.body())
                                }
                                _ => Response::new().with_status(StatusCode::NotFound),
                            })
    }
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = std::fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = std::io::BufReader::new(certfile);
    pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = std::fs::File::open(filename).expect("cannot open private key file");
    let mut reader = std::io::BufReader::new(keyfile);
    let keys = pemfile::rsa_private_keys(&mut reader).unwrap();
    assert!(keys.len() == 1);
    keys[0].clone()
}

fn main() {
    let port = match std::env::args().nth(1) {
        Some(ref p) => p.to_owned(),
        None => "1337".to_owned(),
    };
    let addr = format!("127.0.0.1:{}", port).parse().unwrap();
    let certs = load_certs("examples/sample.pem");
    let key = load_private_key("examples/sample.rsa");
    let mut cfg = rustls::ServerConfig::new();
    cfg.set_single_cert(certs, key);
    let tls = proto::Server::new(Http::new(), std::sync::Arc::new(cfg));
    let tcp = tokio_proto::TcpServer::new(tls, addr);
    println!("Starting to serve on https://{}.", addr);
    tcp.serve(|| Ok(Echo {}));
}
