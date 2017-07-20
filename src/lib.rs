extern crate webpki_roots;
extern crate rustls;
extern crate hyper;

use hyper::net::{HttpStream, SslClient, SslServer, NetworkStream};

use std::io;
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard};
use std::net::{SocketAddr, Shutdown};
use std::time::Duration;

pub struct TlsStream {
  sess: Box<rustls::Session>,
  underlying: HttpStream,
  eof: bool,
  tls_error: Option<rustls::TLSError>,
  io_error: Option<io::Error>
}

impl TlsStream {
  pub fn get_session(&self) -> &rustls::Session {
      self.sess.as_ref()
  }

  pub fn get_mut_session(&mut self) -> &mut rustls::Session {
      self.sess.as_mut()
  }

  fn underlying_read(&mut self) {
    if self.io_error.is_some() || self.tls_error.is_some() {
      return;
    }

    if self.sess.wants_read() {
      match self.sess.read_tls(&mut self.underlying) {
        Err(err) => {
          if err.kind() != io::ErrorKind::WouldBlock {
            self.io_error = Some(err);
          }
        },
        Ok(0) => {
          self.eof = true;
        },
        Ok(_) => ()
      }
    }

    if let Err(err) = self.sess.process_new_packets() {
      self.tls_error = Some(err);
    }
  }

  fn underlying_write(&mut self) {
    if self.io_error.is_some() || self.tls_error.is_some() {
      return;
    }

    while self.io_error.is_none() && self.sess.wants_write() {
      if let Err(err) = self.sess.write_tls(&mut self.underlying) {
        if err.kind() != io::ErrorKind::WouldBlock {
          self.io_error = Some(err);
        }
      }
    }
  }

  fn underlying_io(&mut self) {
    self.underlying_write();
    self.underlying_read();
  }

  fn promote_tls_error(&mut self) -> io::Result<()> {
    match self.tls_error.take() {
      Some(err) => {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, err));
      },
      None => return Ok(())
    };
  }

  fn check_io_error(&mut self) -> io::Result<()> {
    self.io_error.take().map(Err).unwrap_or(Ok(()))
  }

  fn close(&mut self, how: Shutdown) -> io::Result<()> {
    self.underlying.close(how)
  }

  fn peer_addr(&mut self) -> io::Result<SocketAddr> {
    self.underlying.peer_addr()
  }

  fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
    self.underlying.set_read_timeout(dur)
  }

  fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
    self.underlying.set_write_timeout(dur)
  }
}

impl io::Read for TlsStream {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    // This wants to block if we don't have any data ready.
    // underlying_read does this.
    loop {
      try!(self.promote_tls_error());
      try!(self.check_io_error());

      if self.eof {
        return Ok(0);
      }

      match self.sess.read(buf) {
        Ok(0) => self.underlying_io(),
        Ok(n) => return Ok(n),
        Err(e) => return Err(e)
      }
    }
  }
}

impl io::Write for TlsStream {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    let len = try!(self.sess.write(buf));
    try!(self.promote_tls_error());
    self.underlying_write();
    Ok(len)
  }

  fn flush(&mut self) -> io::Result<()> {
    let rc = self.sess.flush();
    try!(self.promote_tls_error());
    self.underlying_write();
    rc
  }
}

#[derive(Clone)]
pub struct WrappedStream(Arc<Mutex<TlsStream>>);

impl WrappedStream {
  fn lock(&self) -> MutexGuard<TlsStream> {
    self.0.lock().unwrap_or_else(|e| e.into_inner())
  }

  /// Lock and return the underlying TlsStream.  This
  /// allows access to the underlying TLS session, for
  /// debugging and custom configuration.
  pub fn to_tls_stream(&self) -> MutexGuard<TlsStream> {
      self.lock()
  }
}

impl io::Read for WrappedStream {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    self.lock().read(buf)
  }
}

impl io::Write for WrappedStream {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    self.lock().write(buf)
  }

  fn flush(&mut self) -> io::Result<()> {
    self.lock().flush()
  }
}

impl NetworkStream for WrappedStream {
  fn peer_addr(&mut self) -> io::Result<SocketAddr> {
    self.lock().peer_addr()
  }

  fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
    self.lock().set_read_timeout(dur)
  }

  fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
    self.lock().set_write_timeout(dur)
  }

  fn close(&mut self, how: Shutdown) -> io::Result<()> {
    self.lock().close(how)
  }
}

#[derive(Clone)]
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

impl SslClient for TlsClient {
  type Stream = WrappedStream;

  fn wrap_client(&self, stream: HttpStream, host: &str) -> hyper::Result<WrappedStream> {
    let tls = TlsStream {
      sess: Box::new(rustls::ClientSession::new(&self.cfg, host)),
      underlying: stream,
      eof: false,
      io_error: None,
      tls_error: None
    };

    Ok(WrappedStream(Arc::new(Mutex::new(tls))))
  }
}

#[derive(Clone)]
pub struct TlsServer {
  pub cfg: Arc<rustls::ServerConfig>
}

impl TlsServer {
  pub fn new(certs: Vec<rustls::Certificate>, key: rustls::PrivateKey) -> TlsServer {
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

impl SslServer for TlsServer {
  type Stream = WrappedStream;

  fn wrap_server(&self, stream: HttpStream) -> hyper::Result<WrappedStream> {
    let tls = TlsStream {
      sess: Box::new(rustls::ServerSession::new(&self.cfg)),
      underlying: stream,
      eof: false,
      io_error: None,
      tls_error: None
    };

    Ok(WrappedStream(Arc::new(Mutex::new(tls))))
  }
}

pub mod util {
  use std::fs;
  use std::io::BufReader;
  use std::io;
  use rustls;

  pub fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    let certfile = try!(fs::File::open(filename));

    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader)
      .map_err(|_| io::Error::new(io::ErrorKind::Other,
                                  "no valid certificates found in file"))
  }

  pub fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    let keyfile = try!(fs::File::open(filename));

    let mut reader = BufReader::new(keyfile);
    let mut keys = try! {
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| io::Error::new(io::ErrorKind::Other,
                                    "no valid keys found in file"))
    };

    match keys.len() {
        1 => Ok(keys.remove(0)),
        0 => Err(io::Error::new(io::ErrorKind::Other, "no keys found in file")),
        _ => Err(io::Error::new(io::ErrorKind::Other, "more than one key in file"))
    }
  }
}
