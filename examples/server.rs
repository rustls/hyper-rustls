#![deny(warnings)]
extern crate hyper;
extern crate hyper_rustls;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate rustls;

use hyper::{Get, Post, StatusCode, RequestUri, Decoder, Encoder, Next};
use hyper::header::ContentLength;
use hyper::server::{Server, Handler, Request, Response};

use std::fs;
use std::io::BufReader;

type HttpStream = hyper_rustls::TlsStream;

struct Echo {
    buf: Vec<u8>,
    read_pos: usize,
    write_pos: usize,
    eof: bool,
    route: Route,
}

enum Route {
    NotFound,
    Index,
    Echo(Body),
}

#[derive(Clone, Copy)]
enum Body {
    Len(u64),
    Chunked
}

static INDEX: &'static [u8] = b"Try POST /echo";

impl Echo {
    fn new() -> Echo {
        Echo {
            buf: vec![0; 4096],
            read_pos: 0,
            write_pos: 0,
            eof: false,
            route: Route::NotFound,
        }
    }
}

impl Handler<HttpStream> for Echo {
    fn on_request(&mut self, req: Request<HttpStream>) -> Next {
        match *req.uri() {
            RequestUri::AbsolutePath { ref path, .. } => match (req.method(), &path[..]) {
                (&Get, "/") | (&Get, "/echo") => {
                    info!("GET Index");
                    self.route = Route::Index;
                    Next::write()
                }
                (&Post, "/echo") => {
                    info!("POST Echo");
                    let mut is_more = true;
                    self.route = if let Some(len) = req.headers().get::<ContentLength>() {
                        is_more = **len > 0;
                        Route::Echo(Body::Len(**len))
                    } else {
                        Route::Echo(Body::Chunked)
                    };
                    if is_more {
                        Next::read_and_write()
                    } else {
                        Next::write()
                    }
                }
                _ => Next::write(),
            },
            _ => Next::write()
        }
    }
    fn on_request_readable(&mut self, transport: &mut Decoder<HttpStream>) -> Next {
        match self.route {
            Route::Echo(ref body) => {
                if self.read_pos < self.buf.len() {
                    match transport.try_read(&mut self.buf[self.read_pos..]) {
                        Ok(Some(0)) => {
                            debug!("Read 0, eof");
                            self.eof = true;
                            Next::write()
                        },
                        Ok(Some(n)) => {
                            self.read_pos += n;
                            match *body {
                                Body::Len(max) if max <= self.read_pos as u64 => {
                                    self.eof = true;
                                    Next::write()
                                },
                                _ => Next::read_and_write()
                            }
                        }
                        Ok(None) => Next::read_and_write(),
                        Err(e) => {
                            println!("read error {:?}", e);
                            Next::end()
                        }
                    }
                } else {
                    Next::write()
                }
            }
            _ => unreachable!()
        }
    }

    fn on_response(&mut self, res: &mut Response) -> Next {
        match self.route {
            Route::NotFound => {
                res.set_status(StatusCode::NotFound);
                Next::end()
            }
            Route::Index => {
                res.headers_mut().set(ContentLength(INDEX.len() as u64));
                Next::write()
            }
            Route::Echo(body) => {
                if let Body::Len(len) = body {
                    res.headers_mut().set(ContentLength(len));
                }
                Next::read_and_write()
            }
        }
    }

    fn on_response_writable(&mut self, transport: &mut Encoder<HttpStream>) -> Next {
        match self.route {
            Route::Index => {
                transport.write(INDEX).unwrap();
                Next::end()
            }
            Route::Echo(..) => {
                if self.write_pos < self.read_pos {
                    match transport.try_write(&self.buf[self.write_pos..self.read_pos]) {
                        Ok(Some(0)) => panic!("write ZERO"),
                        Ok(Some(n)) => {
                            self.write_pos += n;
                            Next::write()
                        }
                        Ok(None) => Next::write(),
                        Err(e) => {
                            println!("write error {:?}", e);
                            Next::end()
                        }
                    }
                } else if !self.eof {
                    Next::read()
                } else {
                    Next::end()
                }
            }
            _ => unreachable!()
        }
    }
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
    let server = Server::https(&"127.0.0.1:1337".parse().unwrap(), tls).unwrap();
    let (listening, server) = server.handle(|_| Echo::new()).unwrap();
    println!("Listening on https://{}", listening);
    server.run();
}
