# hyper-rustls
This is an integration between the [rustls TLS stack](https://github.com/ctz/rustls)
and the [hyper HTTP library](https://github.com/hyperium/hyper).

Implementations are provided of
[`hyper::net::SslClient`](http://hyper.rs/hyper/master/hyper/net/trait.SslClient.html),
[`hyper::net::SslServer`](http://hyper.rs/hyper/master/hyper/net/trait.SslServer.html)
and [`hyper::net::Transport`](http://hyper.rs/hyper/master/hyper/net/trait.Transport.html).
Note that these only exist on hyper master at the moment, so this isn't on crates.io.

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

