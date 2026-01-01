//! Simple HTTPS GET client based on hyper-rustls
//!
//! First parameter is the mandatory URL to GET.
//! Second parameter is an optional path to CA store.
use http::Uri;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_rustls::ConfigBuilderExt;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

use std::str::FromStr;
use std::{env, io};

fn main() {
    // Send GET request and inspect result, with proper error handling.
    if let Err(e) = run_client() {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
async fn run_client() -> io::Result<()> {
    // Set a process wide default crypto provider.
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // First parameter is target URL (mandatory).
    let url = match env::args().nth(1) {
        Some(ref url) => Uri::from_str(url).map_err(|e| error(format!("{e}")))?,
        None => {
            println!("Usage: client <url> <ca_store>");
            return Ok(());
        }
    };

    // Prepare the TLS client config
    let tls = match env::args().nth(2) {
        Some(path) => {
            // Read trust roots
            let certs = CertificateDer::pem_file_iter(&path)
                .and_then(|res| res.collect::<Result<Vec<_>, _>>())
                .map_err(|err| error(format!("could not read CA store {path}: {err}")))?;

            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(certs);
            // TLS client config using the custom CA store for lookups
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        // Default TLS client config with native roots
        None => rustls::ClientConfig::builder()
            .with_native_roots()?
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

    // Prepare a chain of futures which sends a GET request, inspects
    // the returned headers, collects the whole body and prints it to
    // stdout.
    let fut = async move {
        let res = client
            .get(url)
            .await
            .map_err(|e| error(format!("Could not get: {e:?}")))?;
        println!("Status:\n{}", res.status());
        println!("Headers:\n{:#?}", res.headers());

        let body = res
            .into_body()
            .collect()
            .await
            .map_err(|e| error(format!("Could not get body: {e:?}")))?
            .to_bytes();
        println!("Body:\n{}", String::from_utf8_lossy(&body));

        Ok(())
    };

    fut.await
}
