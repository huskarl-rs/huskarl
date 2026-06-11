use huskarl_core::platform::{MaybeSend, MaybeSendSync};
#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
use huskarl_core::secrets::SecretBytes;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "rustls-tls", feature = "native-tls")
))]
use huskarl_core::secrets::{Secret, SecretString};
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "rustls-tls", feature = "native-tls")
))]
use snafu::Snafu;

/// The result of applying an [`MtlsProvider`] to a [`reqwest::ClientBuilder`].
pub struct MtlsApplyOutput {
    /// The builder with mTLS configured.
    pub builder: reqwest::ClientBuilder,
    /// The identity that was applied, if any. `None` for [`NoMtls`].
    ///
    /// Stored by [`crate::ReqwestClient`] so the identity can be reused when
    /// building additional clients with different root certificates.
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "rustls-tls", feature = "native-tls")
    ))]
    pub identity: Option<reqwest::Identity>,
}

/// Trait for configuring mTLS on a `reqwest::ClientBuilder`.
pub trait MtlsProvider: MaybeSendSync {
    /// The error type returned by this provider.
    type Error: huskarl_core::Error + 'static;

    /// Applies the mTLS configuration to the provided builder.
    fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> impl Future<Output = Result<MtlsApplyOutput, Self::Error>> + MaybeSend;

    /// Returns true if this provider configures mTLS.
    fn uses_mtls(&self) -> bool;
}

/// A no-op mTLS provider.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMtls;

impl MtlsProvider for NoMtls {
    type Error = std::convert::Infallible;

    async fn apply(&self, builder: reqwest::ClientBuilder) -> Result<MtlsApplyOutput, Self::Error> {
        Ok(MtlsApplyOutput {
            builder,
            #[cfg(all(
                not(target_arch = "wasm32"),
                any(feature = "rustls-tls", feature = "native-tls")
            ))]
            identity: None,
        })
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

/// Errors that can occur when configuring mTLS from a PEM identity.
#[cfg(all(not(target_arch = "wasm32"), feature = "rustls-tls"))]
#[derive(Debug, Snafu)]
pub enum MtlsPemError<E: huskarl_core::Error + 'static> {
    /// Failed to fetch the secret value.
    #[snafu(display("Failed to fetch mTLS secret"))]
    FetchSecret {
        /// The underlying secret error.
        source: E,
    },
    /// Failed to parse the identity.
    #[snafu(display("Failed to parse mTLS identity"))]
    ParseIdentity {
        /// The underlying reqwest error.
        source: reqwest::Error,
    },
}

#[cfg(all(not(target_arch = "wasm32"), feature = "rustls-tls"))]
impl<E: huskarl_core::Error + 'static> huskarl_core::Error for MtlsPemError<E> {
    fn is_retryable(&self) -> bool {
        match self {
            Self::FetchSecret { source } => source.is_retryable(),
            Self::ParseIdentity { .. } => false,
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "rustls-tls"))]
impl<S: Secret<Output = SecretString>> MtlsProvider for MtlsPem<S> {
    type Error = MtlsPemError<S::Error>;

    async fn apply(&self, builder: reqwest::ClientBuilder) -> Result<MtlsApplyOutput, Self::Error> {
        use snafu::ResultExt;
        let secret_output = self
            .secret
            .get_secret_value()
            .await
            .context(FetchSecretSnafu)?;
        let identity = reqwest::Identity::from_pem(secret_output.value.expose_secret().as_bytes())
            .context(ParseIdentitySnafu)?;
        Ok(MtlsApplyOutput {
            builder: builder.identity(identity.clone()),
            identity: Some(identity),
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

/// Errors that can occur when configuring mTLS from a PKCS#12 archive.
#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum MtlsPkcs12Error<DE: huskarl_core::Error + 'static, PE: huskarl_core::Error + 'static> {
    /// Failed to fetch the DER secret.
    #[snafu(display("Failed to fetch mTLS DER secret"))]
    FetchDer {
        /// The underlying secret error.
        source: DE,
    },
    /// Failed to fetch the password secret.
    #[snafu(display("Failed to fetch mTLS password secret"))]
    FetchPassword {
        /// The underlying secret error.
        source: PE,
    },
    /// Failed to parse the PKCS#12 identity.
    #[snafu(display("Failed to parse mTLS identity"))]
    ParseIdentity {
        /// The underlying reqwest error.
        source: reqwest::Error,
    },
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
impl<DE: huskarl_core::Error + 'static, PE: huskarl_core::Error + 'static> huskarl_core::Error
    for MtlsPkcs12Error<DE, PE>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::FetchDer { source } => source.is_retryable(),
            Self::FetchPassword { source } => source.is_retryable(),
            Self::ParseIdentity { .. } => false,
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
impl<D: Secret<Output = SecretBytes>, P: Secret<Output = SecretString>> MtlsProvider
    for MtlsPkcs12<D, P>
{
    type Error = MtlsPkcs12Error<D::Error, P::Error>;

    async fn apply(&self, builder: reqwest::ClientBuilder) -> Result<MtlsApplyOutput, Self::Error> {
        use mtls_pkcs12_error::*;
        use snafu::ResultExt;
        let der = self.der.get_secret_value().await.context(FetchDerSnafu)?;
        let password = self
            .password
            .get_secret_value()
            .await
            .context(FetchPasswordSnafu)?;
        let identity = reqwest::Identity::from_pkcs12_der(
            der.value.expose_secret(),
            password.value.expose_secret(),
        )
        .context(ParseIdentitySnafu)?;
        Ok(MtlsApplyOutput {
            builder: builder.identity(identity.clone()),
            identity: Some(identity),
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

/// Errors that can occur when configuring mTLS from a PKCS#8 PEM identity.
#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum MtlsPkcs8PemError<KE: huskarl_core::Error + 'static> {
    /// Failed to fetch the private key secret.
    #[snafu(display("Failed to fetch mTLS private key secret"))]
    FetchKey {
        /// The underlying secret error.
        source: KE,
    },
    /// Failed to parse the PKCS#8 PEM identity.
    #[snafu(display("Failed to parse mTLS identity"))]
    ParseIdentity {
        /// The underlying reqwest error.
        source: reqwest::Error,
    },
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
impl<KE: huskarl_core::Error + 'static> huskarl_core::Error for MtlsPkcs8PemError<KE> {
    fn is_retryable(&self) -> bool {
        match self {
            Self::FetchKey { source } => source.is_retryable(),
            Self::ParseIdentity { .. } => false,
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-tls"))]
impl<K: Secret<Output = SecretString>> MtlsProvider for MtlsPkcs8Pem<K> {
    type Error = MtlsPkcs8PemError<K::Error>;

    async fn apply(&self, builder: reqwest::ClientBuilder) -> Result<MtlsApplyOutput, Self::Error> {
        use mtls_pkcs8_pem_error::*;
        use snafu::ResultExt;
        let key = self.key.get_secret_value().await.context(FetchKeySnafu)?;
        let identity = reqwest::Identity::from_pkcs8_pem(
            self.cert_chain.as_bytes(),
            key.value.expose_secret().as_bytes(),
        )
        .context(ParseIdentitySnafu)?;
        Ok(MtlsApplyOutput {
            builder: builder.identity(identity.clone()),
            identity: Some(identity),
        })
    }

    fn uses_mtls(&self) -> bool {
        true
    }
}
