// Copied from hyperium/hyper-tls#62e3376/src/stream.rs

use bytes::{Buf, BufMut};
use futures::Poll;
use std::fmt;
use std::io::{self, Read, Write};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;

/// A stream that might be protected with TLS.
pub enum MaybeHttpsStream<T> {
    /// A stream over plain text.
    Http(T),
    /// A stream protected with TLS.
    Https(TlsStream<T>),
}

impl<T: fmt::Debug> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}

impl<T: Read + Write> Read for MaybeHttpsStream<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.read(buf),
            MaybeHttpsStream::Https(ref mut s) => {
                let (_, cs) = s.get_mut();
                cs.read(buf)
            }
        }
    }
}

impl<T: Read + Write> Write for MaybeHttpsStream<T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.write(buf),
            MaybeHttpsStream::Https(ref mut s) => {
                let (_, cs) = s.get_mut();
                cs.write(buf)
            }
        }
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.flush(),
            MaybeHttpsStream::Https(ref mut s) => {
                let (_, cs) = s.get_mut();
                cs.flush()
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncRead for MaybeHttpsStream<T> {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        match *self {
            MaybeHttpsStream::Http(ref s) => s.prepare_uninitialized_buffer(buf),
            MaybeHttpsStream::Https(ref s) => s.prepare_uninitialized_buffer(buf),
        }
    }

    fn read_buf<B: BufMut>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.read_buf(buf),
            MaybeHttpsStream::Https(ref mut s) => s.read_buf(buf),
        }
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncWrite for MaybeHttpsStream<T> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.shutdown(),
            MaybeHttpsStream::Https(ref mut s) => s.shutdown(),
        }
    }

    fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.write_buf(buf),
            MaybeHttpsStream::Https(ref mut s) => s.write_buf(buf),
        }
    }
}
