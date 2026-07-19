//! mTLS configuration for [`ReqwestClient`](crate::ReqwestClient).

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "rustls-tls", feature = "native-tls")
))]
use huskarl_core::ErrorKind;
#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
use huskarl_core::secrets::SecretBytes;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "rustls-tls", feature = "native-tls")
))]
use huskarl_core::secrets::{Secret, SecretString};
use huskarl_core::{
    Error,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
};

/// A [`reqwest::ClientBuilder`] with an [`MtlsProvider`]'s configuration
/// applied, as returned from [`MtlsProvider::apply`].
///
/// Construct with [`ConfiguredBuilder::new`]; providers that installed an
/// identity record it with [`with_identity`](ConfiguredBuilder::with_identity).
pub struct ConfiguredBuilder {
    pub(crate) builder: reqwest::ClientBuilder,
    /// The identity that was applied, if any. Stored by
    /// [`crate::ReqwestClient`] so the identity can be reused when building
    /// additional clients with different root certificates.
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "rustls-tls", feature = "native-tls")
    ))]
    pub(crate) identity: Option<reqwest::Identity>,
}

impl ConfiguredBuilder {
    /// Wraps the configured builder, with no identity recorded.
    #[must_use]
    pub fn new(builder: reqwest::ClientBuilder) -> Self {
        Self {
            builder,
            #[cfg(all(
                not(target_arch = "wasm32"),
                any(feature = "rustls-tls", feature = "native-tls")
            ))]
            identity: None,
        }
    }

    /// Records the identity the provider applied, so
    /// [`ReqwestClient::identity`](crate::ReqwestClient::identity) can expose
    /// it for reuse.
    ///
    /// Requires the `rustls-tls` or `native-tls` feature.
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "rustls-tls", feature = "native-tls")
    ))]
    #[must_use]
    pub fn with_identity(mut self, identity: reqwest::Identity) -> Self {
        self.identity = Some(identity);
        self
    }
}

/// Trait for configuring mTLS on a `reqwest::ClientBuilder`.
///
/// This trait is dyn-capable: implement it on your provider type, write the
/// method body as `Box::pin(async move { ... })`, and return the configured
/// builder via [`ConfiguredBuilder::new`]. Secret-fetch failures should be
/// propagated as-is (they are already classified); identity-parse failures
/// should be classified as [`ErrorKind::Config`](huskarl_core::ErrorKind).
pub trait MtlsProvider: MaybeSendSync {
    /// Applies the mTLS configuration to the provided builder.
    fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> MaybeSendBoxFuture<'_, Result<ConfiguredBuilder, Error>>;

    /// Returns true if this provider configures mTLS.
    fn uses_mtls(&self) -> bool;
}

/// A no-op mTLS provider.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMtls;

impl MtlsProvider for NoMtls {
    fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> MaybeSendBoxFuture<'_, Result<ConfiguredBuilder, Error>> {
        Box::pin(async move { Ok(ConfiguredBuilder::new(builder)) })
    }

    fn uses_mtls(&self) -> bool {
        false
    }
}

/// An mTLS provider using a combined PEM-encoded private key and certificate chain.
///
/// The secret should contain a PEM-encoded private key (RSA, SEC1 EC, or PKCS#8) followed by one
/// or more PEM-encoded certificates. Uses [`reqwest::Identity::from_pem`].
///
/// Requires the `rustls-tls` feature.
#[cfg(all(not(target_arch = "wasm32"), feature = "rustls-tls"))]
pub struct MtlsPem<S: Secret<Output = SecretString>> {
    secret: S,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "rustls-tls"))]
impl<S: Secret<Output = SecretString>> MtlsPem<S> {
    /// Creates a new `MtlsPem` provider from the given secret.
    pub fn new(secret: S) -> Self {
        Self { secret }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "rustls-tls"))]
impl<S: Secret<Output = SecretString>> MtlsProvider for MtlsPem<S> {
    fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> MaybeSendBoxFuture<'_, Result<ConfiguredBuilder, Error>> {
        Box::pin(async move {
            let secret_output = self
                .secret
                .get_secret_value()
                .await
                .map_err(|e| e.with_context("fetching mTLS secret"))?;
            let identity =
                reqwest::Identity::from_pem(secret_output.value.expose_secret().as_bytes())
                    .map_err(parse_identity_error)?;
            Ok(ConfiguredBuilder::new(builder.identity(identity.clone())).with_identity(identity))
        })
    }

    fn uses_mtls(&self) -> bool {
        true
    }
}

/// An mTLS provider using a PKCS#12 DER-encoded archive with a password.
///
/// Uses [`reqwest::Identity::from_pkcs12_der`].
///
/// Requires the `native-tls` feature.
#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
pub struct MtlsPkcs12<D: Secret<Output = SecretBytes>, P: Secret<Output = SecretString>> {
    der: D,
    password: P,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
impl<D: Secret<Output = SecretBytes>, P: Secret<Output = SecretString>> MtlsPkcs12<D, P> {
    /// Creates a new `MtlsPkcs12` provider from the given DER and password secrets.
    pub fn new(der: D, password: P) -> Self {
        Self { der, password }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
impl<D: Secret<Output = SecretBytes>, P: Secret<Output = SecretString>> MtlsProvider
    for MtlsPkcs12<D, P>
{
    fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> MaybeSendBoxFuture<'_, Result<ConfiguredBuilder, Error>> {
        Box::pin(async move {
            let der = self
                .der
                .get_secret_value()
                .await
                .map_err(|e| e.with_context("fetching mTLS DER secret"))?;
            let password = self
                .password
                .get_secret_value()
                .await
                .map_err(|e| e.with_context("fetching mTLS password secret"))?;
            let identity = reqwest::Identity::from_pkcs12_der(
                der.value.expose_secret(),
                password.value.expose_secret(),
            )
            .map_err(parse_identity_error)?;
            Ok(ConfiguredBuilder::new(builder.identity(identity.clone())).with_identity(identity))
        })
    }

    fn uses_mtls(&self) -> bool {
        true
    }
}

/// An mTLS provider using separate PEM-encoded certificate chain and PKCS#8 private key.
///
/// The certificate chain is public data; only the private key is treated as a secret.
/// Uses [`reqwest::Identity::from_pkcs8_pem`].
///
/// Requires the `native-tls` feature.
#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
pub struct MtlsPkcs8Pem<K: Secret<Output = SecretString>> {
    cert_chain: String,
    key: K,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
impl<K: Secret<Output = SecretString>> MtlsPkcs8Pem<K> {
    /// Creates a new `MtlsPkcs8Pem` provider from the given certificate chain and key secret.
    pub fn new(cert_chain: impl Into<String>, key: K) -> Self {
        Self {
            cert_chain: cert_chain.into(),
            key,
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
impl<K: Secret<Output = SecretString>> MtlsProvider for MtlsPkcs8Pem<K> {
    fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> MaybeSendBoxFuture<'_, Result<ConfiguredBuilder, Error>> {
        Box::pin(async move {
            let key = self
                .key
                .get_secret_value()
                .await
                .map_err(|e| e.with_context("fetching mTLS private key secret"))?;
            let identity = reqwest::Identity::from_pkcs8_pem(
                self.cert_chain.as_bytes(),
                key.value.expose_secret().as_bytes(),
            )
            .map_err(parse_identity_error)?;
            Ok(ConfiguredBuilder::new(builder.identity(identity.clone())).with_identity(identity))
        })
    }

    fn uses_mtls(&self) -> bool {
        true
    }
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "rustls-tls", feature = "native-tls")
))]
fn parse_identity_error(source: reqwest::Error) -> Error {
    Error::new(ErrorKind::Config, source).with_context("parsing mTLS identity")
}
