use rustls::client::WantsClientCert;
use rustls::{ClientConfig, ConfigBuilder, WantsVerifier};

/// Methods for configuring roots
///
/// This adds methods (gated by crate features) for easily configuring
/// TLS server roots a rustls ClientConfig will trust.
pub trait ConfigBuilderExt {
    /// This configures the platform's trusted certs, as implemented by
    /// rustls-native-certs
    #[cfg(all(feature = "rustls-native-certs", feature = "ring"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls-native-certs")))]
    fn with_native_roots(self) -> std::io::Result<ConfigBuilder<ClientConfig, WantsClientCert>>;

    /// This configures the webpki roots, which are Mozilla's set of
    /// trusted roots as packaged by webpki-roots.
    #[cfg(all(feature = "webpki-roots", feature = "ring"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "webpki-roots")))]
    fn with_webpki_roots(self) -> ConfigBuilder<ClientConfig, WantsClientCert>;
}

impl ConfigBuilderExt for ConfigBuilder<ClientConfig, WantsVerifier> {
    #[cfg(all(feature = "rustls-native-certs", feature = "ring"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls-native-certs")))]
    #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
    fn with_native_roots(self) -> std::io::Result<ConfigBuilder<ClientConfig, WantsClientCert>> {
        let mut roots = rustls::RootCertStore::empty();
        let mut valid_count = 0;
        let mut invalid_count = 0;

        for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs")
        {
            match roots.add(cert.as_ref().into()) {
                Ok(_) => valid_count += 1,
                Err(err) => {
                    crate::log::trace!("invalid cert der {:?}", cert.as_ref());
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

    #[cfg(all(feature = "webpki-roots", feature = "ring"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "webpki-roots")))]
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
