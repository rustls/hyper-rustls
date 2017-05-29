# hyper-rustls
This is an integration between the [rustls TLS stack](https://github.com/ctz/rustls)
and the [hyper HTTP library](https://github.com/hyperium/hyper).

[![Build Status](https://travis-ci.org/ctz/hyper-rustls.svg?branch=master)](https://travis-ci.org/ctz/hyper-rustls)
[![Crate](https://img.shields.io/crates/v/hyper-rustls.svg)](https://crates.io/crates/hyper-rustls)

[API Documentation](https://docs.rs/hyper-rustls/)

Implementations are provided of
[`hyper::net::SslClient`](http://hyper.rs/hyper/v0.9.10/hyper/net/trait.SslClient.html),
[`hyper::net::SslServer`](http://hyper.rs/hyper/v0.9.10/hyper/net/trait.SslServer.html)
and [`hyper::net::NetworkStream`](http://hyper.rs/hyper/v0.9.10/hyper/net/trait.NetworkStream.html).

By default clients verify certificates using the `webpki-roots` crate, which includes
the Mozilla root CAs.

# License
hyper-rustls is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.

