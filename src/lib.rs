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
//! use hyper::{Client, Uri};
//! use tokio_core::reactor;
//!
//! fn main() {
//!     let mut core = reactor::Core::new().unwrap();
//!     let url = ("https://hyper.rs").parse().unwrap();
//!
//!     let client = hyper::Client::configure()
//!         .connector(hyper_rustls::HttpsConnector::new(4, &core.handle()))
//!         .build(&core.handle());
//!
//!     let res = core.run(client.get(url)).unwrap();
//!     assert_eq!(res.status(), hyper::Ok);
//! }
//! ```

extern crate futures;
extern crate hyper;
extern crate rustls;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_rustls;
extern crate tokio_service;
extern crate webpki;
extern crate webpki_roots;
extern crate ct_logs;

mod connector;
mod stream;

pub use connector::HttpsConnector;
pub use stream::MaybeHttpsStream;
