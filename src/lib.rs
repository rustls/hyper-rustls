//! # hyper-rustls
//!
//! A pure-Rust HTTPS connector for [hyper](https://hyper.rs), based on [Rustls](https://github.com/ctz/rustls).
//!
//! ## Example
//!
//! ```no_run
//! # #[cfg(feature = "tokio-runtime")]
//! # extern crate hyper;
//! #
//! # #[cfg(feature = "tokio-runtime")]
//! # fn main() {
//! use hyper::{Body, Client, StatusCode, Uri};
//!
//! let mut rt = tokio::runtime::Runtime::new().unwrap();
//! let url = ("https://hyper.rs").parse().unwrap();
//! let https = hyper_rustls::HttpsConnector::new(4);
//!
//! let client: Client<_, hyper::Body> = Client::builder().build(https);
//!
//! let res = rt.block_on(client.get(url)).unwrap();
//! assert_eq!(res.status(), StatusCode::OK);
//! # }
//! # #[cfg(not(feature = "tokio-runtime"))]
//! # fn main() {}
//! ```

extern crate bytes;
#[cfg(feature = "tokio-runtime")]
extern crate ct_logs;
extern crate futures;
extern crate hyper;
extern crate rustls;
extern crate tokio_io;
extern crate tokio_rustls;
extern crate webpki;
#[cfg(feature = "tokio-runtime")]
extern crate webpki_roots;

mod connector;
mod stream;

pub use connector::HttpsConnector;
pub use stream::MaybeHttpsStream;
