extern crate webpki_roots;
extern crate rustls;
extern crate hyper;
extern crate rotor;
extern crate vecio;

use hyper::net::{HttpStream, Blocked, Transport};
use rotor::mio;

use std::io;
use std::sync::Arc;

pub struct TlsStream {
  sess: Box<rustls::Session>,
  underlying: HttpStream,
  tls_error: Option<rustls::TLSError>,
  io_error: Option<io::Error>
}

impl TlsStream {
  fn underlying_io(&mut self) {
    if self.io_error.is_some() || self.tls_error.is_some() {
      return;
    }

    if self.io_error.is_none() && self.sess.wants_read() {
      if let Err(err) = self.sess.read_tls(&mut self.underlying) {
        if err.kind() != io::ErrorKind::WouldBlock {
          self.io_error = Some(err);
        }
      }
    }

    if let Err(err) = self.sess.process_new_packets() {
      self.tls_error = Some(err);
    }
    
    if self.io_error.is_none() && self.sess.wants_write() {
      if let Err(err) = self.sess.write_tls(&mut self.underlying) {
        if err.kind() != io::ErrorKind::WouldBlock {
          self.io_error = Some(err);
        }
      }
    }
  }
    
  fn promote_tls_error(&mut self) -> io::Result<()> {
    match self.tls_error.take() {
      Some(err) => {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, err));
      },
      None => return Ok(())
    };
  }
}

impl Transport for TlsStream {
  fn take_socket_error(&mut self) -> io::Result<()> {
    match self.io_error.take() {
      Some(err) => Err(err),
      None => Ok(())
    }
  }

  fn blocked(&self) -> Option<Blocked> {
    if self.sess.wants_write() {
      return Some(Blocked::Write);
    }

    None
  }
}

impl io::Read for TlsStream {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    self.underlying_io();
    try!(self.promote_tls_error());
    match self.sess.read(buf) {
      Err(err) => Err(err),
      Ok(0) => Err(io::Error::new(io::ErrorKind::WouldBlock, "would block")),
      Ok(n) => Ok(n)
    }
  }
}

impl io::Write for TlsStream {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    let len = try!(self.sess.write(buf));
    try!(self.promote_tls_error());
    self.underlying_io();
    Ok(len)
  }

  fn flush(&mut self) -> io::Result<()> {
    let rc = self.sess.flush();
    try!(self.promote_tls_error());
    self.underlying_io();
    rc
  }
}

impl mio::Evented for TlsStream {
  fn register(&self, selector: &mut mio::Selector, token: mio::Token,
              interest: mio::EventSet, opts: mio::PollOpt) -> io::Result<()> {
    self.underlying.register(selector, token, interest, opts)
  }

  fn reregister(&self, selector: &mut mio::Selector, token: mio::Token,
                interest: mio::EventSet, opts: mio::PollOpt) -> io::Result<()> {
    self.underlying.reregister(selector, token, interest, opts)
  }

  fn deregister(&self, selector: &mut mio::Selector) -> io::Result<()> {
    self.underlying.deregister(selector)
  }
}

impl vecio::Writev for TlsStream {
  fn writev(&mut self, bufs: &[&[u8]]) -> io::Result<usize> {
    use std::io::Write;
    let vec = bufs.concat();
    self.write(&vec)
  }
}

pub struct TlsClient {
  pub cfg: Arc<rustls::ClientConfig>
}

impl TlsClient {
  pub fn new() -> TlsClient {
    let mut tls_config = rustls::ClientConfig::new();
    let cache = rustls::ClientSessionMemoryCache::new(64);
    tls_config.set_persistence(cache);
    tls_config.root_store.add_trust_anchors(&webpki_roots::ROOTS);

    TlsClient {
      cfg: Arc::new(tls_config)
    }
  }
}

impl hyper::net::SslClient for TlsClient {
  type Stream = TlsStream;

  fn wrap_client(&self, stream: HttpStream, host: &str) -> hyper::Result<TlsStream> {
    let tls = TlsStream {
      sess: Box::new(rustls::ClientSession::new(&self.cfg, host)),
      underlying: stream,
      io_error: None,
      tls_error: None
    };

    Ok(tls)
  }
}

pub struct TlsServer {
  pub cfg: Arc<rustls::ServerConfig>
}

impl TlsServer {
  pub fn new(certs: Vec<Vec<u8>>, key: Vec<u8>) -> TlsServer {
    let mut tls_config = rustls::ServerConfig::new();
    let cache = rustls::ServerSessionMemoryCache::new(1024);
    tls_config.set_persistence(cache);
    tls_config.ticketer = rustls::Ticketer::new();
    tls_config.set_single_cert(certs, key);

    TlsServer {
      cfg: Arc::new(tls_config)
    }
  }
}

impl hyper::net::SslServer for TlsServer {
  type Stream = TlsStream;

  fn wrap_server(&self, stream: HttpStream) -> hyper::Result<TlsStream> {
    let tls = TlsStream {
      sess: Box::new(rustls::ServerSession::new(&self.cfg)),
      underlying: stream,
      io_error: None,
      tls_error: None
    };

    Ok(tls)
  }
}
