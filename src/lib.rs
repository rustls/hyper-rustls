//! # hyper-rustls
//!
//! A pure-Rust HTTPS connector for [hyper](https://hyper.rs), based on [Rustls](https://github.com/ctz/rustls).
//!
//! ## Example
//!
//! ```no_run
//! extern crate hyper;
//! extern crate hyper_rustls;
//! extern crate tokio_core;
//!
//! use hyper::{Body, Client, StatusCode, Uri};
//! use tokio_core::reactor;
//!
//! fn main() {
//!     let mut core = reactor::Core::new().unwrap();
//!     let url = ("https://hyper.rs").parse().unwrap();
//!     let https = hyper_rustls::HttpsConnector::new(4);
//!
//!     let client: Client<_, hyper::Body> = Client::builder().build(https);
//!
//!     let res = core.run(client.get(url)).unwrap();
//!     assert_eq!(res.status(), StatusCode::OK);
//! }
//! ```

extern crate ct_logs;
extern crate futures;
extern crate http;
extern crate hyper;
extern crate rustls;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_reactor;
extern crate tokio_rustls;
extern crate tokio_tcp;
extern crate webpki;
extern crate webpki_roots;

mod connector;
mod stream;

pub use connector::HttpsConnector;
pub use stream::MaybeHttpsStream;
