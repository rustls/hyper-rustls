# hyper-rustls
This is an integration between the [rustls rust TLS stack](https://github.com/ctz/rustls)
and the [hyper rust HTTP library](https://github.com/hyperium/hyper).

Implementations are provided of
[`hyper::net::SslClient`](http://hyper.rs/hyper/master/hyper/net/trait.SslClient.html),
[`hyper::net::SslServer`](http://hyper.rs/hyper/master/hyper/net/trait.SslServer.html)
and [`hyper::net::Transport`](http://hyper.rs/hyper/master/hyper/net/trait.Transport.html).
Note that these only exist on hyper master at the moment.

By default clients verify certificates using the `webpki-roots` crate, which includes
the Mozilla root CAs.
