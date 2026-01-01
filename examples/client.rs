//! Simple HTTPS GET client based on hyper-rustls
//!
//! First parameter is the mandatory URL to GET.
//! Second parameter is an optional path to CA store.

use http::Uri;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_rustls::ConfigBuilderExt;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use pki_types::{pem::PemObject, CertificateDer};
use rustls::{ClientConfig, RootCertStore};

use std::str::FromStr;
use std::{env, fs, io};

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Set a process wide default crypto provider.
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // First parameter is target URL (mandatory).
    let url = match env::args().nth(1) {
        Some(u) => Uri::from_str(&u).map_err(|e| error(e.to_string()))?,
        None => return Ok(()),
    };

    // Prepare the TLS client config
    let tls = match env::args().nth(2) {
        Some(path) => {
            let data = fs::read(&path).map_err(|e| error(format!("failed to open {path}: {e}")))?;

            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(&data) {
                let cert = cert.map_err(|e| error(format!("invalid PEM: {e}")))?;
                roots.add_parsable_certificates([cert]);
            }

            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        // Default TLS client config with native roots
        None => ClientConfig::builder()
            .with_native_roots()
            .map_err(|e| error(e.to_string()))?
            .with_no_client_auth(),
    };
    // Prepare the HTTPS connector
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();

    // Build the hyper client from the HTTPS connector.
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    // Send the request and print the response.
    let res = client
        .get(url)
        .await
        .map_err(|e| error(format!("request failed: {e:?}")))?;

    let status = res.status();
    let headers = res.headers().clone();

    let body = res
        .into_body()
        .collect()
        .await
        .map_err(|e| error(format!("body error: {e:?}")))?
        .to_bytes();

    println!("Status:\n{status}");
    println!("Headers:\n{headers:#?}");
    println!("Body:\n{}", String::from_utf8_lossy(&body));

    Ok(())
}
