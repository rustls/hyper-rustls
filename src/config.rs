#[cfg(any(feature = "rustls-native-certs", feature = "webpki-roots"))]
use rustls::client::WantsClientCert;
use rustls::{ClientConfig, ConfigBuilder, WantsVerifier};

/// Methods for configuring roots
///
/// This adds methods (gated by crate features) for easily configuring
/// TLS server roots a rustls ClientConfig will trust.
pub trait ConfigBuilderExt {
    /// This configures the platform's trusted certs, as implemented by
    /// rustls-native-certs
    ///
    /// This will return an error if no valid certs were found. In that case,
    /// it's recommended to use `with_webpki_roots`.
    #[cfg(feature = "rustls-native-certs")]
    fn with_native_roots(self) -> std::io::Result<ConfigBuilder<ClientConfig, WantsClientCert>>;

    /// This configures the webpki roots, which are Mozilla's set of
    /// trusted roots as packaged by webpki-roots.
    #[cfg(feature = "webpki-roots")]
    fn with_webpki_roots(self) -> ConfigBuilder<ClientConfig, WantsClientCert>;
}

impl ConfigBuilderExt for ConfigBuilder<ClientConfig, WantsVerifier> {
    #[cfg(feature = "rustls-native-certs")]
    #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
    fn with_native_roots(self) -> std::io::Result<ConfigBuilder<ClientConfig, WantsClientCert>> {
        let mut roots = rustls::RootCertStore::empty();
        let mut valid_count = 0;
        let mut invalid_count = 0;

        for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs")
        {
            match roots.add(cert) {
                Ok(_) => valid_count += 1,
                Err(err) => {
                    crate::log::debug!("certificate parsing failed: {:?}", err);
                    invalid_count += 1
                }
            }
        }
        crate::log::debug!(
            "with_native_roots processed {} valid and {} invalid certs",
            valid_count,
            invalid_count
        );
        if roots.is_empty() {
            crate::log::debug!("no valid native root CA certificates found");
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no valid native root CA certificates found ({invalid_count} invalid)"),
            ))?
        }

        Ok(self.with_root_certificates(roots))
    }

    #[cfg(feature = "webpki-roots")]
    fn with_webpki_roots(self) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
        self.with_root_certificates(roots)
    }
}
