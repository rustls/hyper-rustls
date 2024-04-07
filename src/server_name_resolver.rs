use std::error::Error;

use http::Uri;
use pki_types::ServerName;

/// A trait implemented by types that can resolve a [`ServerName`] for a request.
pub trait ResolveServerName {
    /// Maps a [`Uri`] into a [`ServerName`].
    fn resolve(&self, uri: &Uri) -> Result<ServerName<'static>, Box<dyn Error + Sync + Send>>;
}

impl<F, E> ResolveServerName for F
where
    F: Fn(&Uri) -> Result<ServerName<'static>, E>,
    E: Into<Box<dyn Error + Sync + Send>>,
{
    fn resolve(&self, uri: &Uri) -> Result<ServerName<'static>, Box<dyn Error + Sync + Send>> {
        self(uri).map_err(Into::into)
    }
}

pub(crate) struct FixedServerNameResolver {
    name: String,
}

impl FixedServerNameResolver {
    pub(crate) fn new(mut name: String) -> Self {
        // Remove square brackets around IPv6 address.
        if let Some(trimmed) = name
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
        {
            name = trimmed.to_string();
        }

        Self { name }
    }
}

impl ResolveServerName for FixedServerNameResolver {
    fn resolve(&self, _: &Uri) -> Result<ServerName<'static>, Box<dyn Error + Sync + Send>> {
        ServerName::try_from(self.name.clone()).map_err(|e| Box::new(e) as _)
    }
}
