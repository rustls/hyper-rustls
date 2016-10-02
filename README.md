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

# Examples
These are provided as an example of the minimal changes needed to
use rustls in your existing hyper-using program.

Note that these are derived works of original hyper source, and are
distributed under hyper's license.

## Client

```
@@ -1,6 +1,8 @@
 #![deny(warnings)]
 extern crate hyper;
 
+extern crate hyper_rustls;
+
 extern crate env_logger;
 
 use std::env;
@@ -8,13 +10,15 @@
 use std::sync::mpsc;
 use std::time::Duration;
 
-use hyper::client::{Client, Request, Response, DefaultTransport as HttpStream};
+use hyper::client::{Config, Request, Response};
 use hyper::header::Connection;
 use hyper::{Decoder, Encoder, Next};
 
 #[derive(Debug)]
 struct Dump(mpsc::Sender<()>);
 
+type HttpStream = hyper::net::HttpsStream<hyper_rustls::TlsStream>;
+
 impl Drop for Dump {
     fn drop(&mut self) {
         let _ = self.0.send(());
@@ -73,7 +77,11 @@
     };
 
     let (tx, rx) = mpsc::channel();
-    let client = Client::new().expect("Failed to create a Client");
+    let connector = hyper::client::HttpsConnector::new(hyper_rustls::TlsClient::new());
+    let client = Config::default()
+        .connector(connector)
+        .build()
+        .expect("Failed to create a Client");
     client.request(url.parse().unwrap(), Dump(tx)).unwrap();
 
     // wait till done
```

## Server

```
@@ -1,13 +1,20 @@
 #![deny(warnings)]
 extern crate hyper;
+extern crate hyper_rustls;
 extern crate env_logger;
 #[macro_use]
 extern crate log;
+extern crate rustls;
 
-use hyper::{Get, Post, StatusCode, RequestUri, Decoder, Encoder, HttpStream, Next};
+use hyper::{Get, Post, StatusCode, RequestUri, Decoder, Encoder, Next};
 use hyper::header::ContentLength;
 use hyper::server::{Server, Handler, Request, Response};
 
+use std::fs;
+use std::io::BufReader;
+
+type HttpStream = hyper_rustls::TlsStream;
+
 struct Echo {
     buf: Vec<u8>,
     read_pos: usize,
@@ -155,9 +162,30 @@
     }
 }
 
+fn load_certs(filename: &str) -> Vec<Vec<u8>> {
+    let certfile = fs::File::open(filename)
+        .expect("cannot open certificate file");
+    let mut reader = BufReader::new(certfile);
+    rustls::internal::pemfile::certs(&mut reader)
+      .unwrap()
+}
+
+fn load_private_key(filename: &str) -> Vec<u8> {
+    let keyfile = fs::File::open(filename)
+        .expect("cannot open private key file");
+    let mut reader = BufReader::new(keyfile);
+    let keys = rustls::internal::pemfile::rsa_private_keys(&mut reader)
+        .unwrap();
+    assert!(keys.len() == 1);
+    keys[0].clone()
+}
+
 fn main() {
     env_logger::init().unwrap();
-    let server = Server::http(&"127.0.0.1:1337".parse().unwrap()).unwrap();
+    let certs = load_certs("examples/sample.pem");
+    let key = load_private_key("examples/sample.rsa");
+    let tls = hyper_rustls::TlsServer::new(certs, key);
+    let server = Server::https(&"127.0.0.1:1337".parse().unwrap(), tls).unwrap();
     let (listening, server) = server.handle(|_| Echo::new()).unwrap();
     println!("Listening on http://{}", listening);
     server.run();
```

# License
hyper-rustls is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.

