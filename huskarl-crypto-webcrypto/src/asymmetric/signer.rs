//! JWS signing with asymmetric private keys via the WebCrypto/SubtleCrypto API,
//! backing huskarl-core's [`JwsSigner`] / [`AsymmetricJwsSigner`] traits.
//!
//! [`PrivateKey`] is the entry type; generate one with [`PrivateKey::generate`].
//! Because `WebCrypto` is async, construction and signing are `async`.
//!
//! The following JWS algorithms are available:
//!
//! - Asymmetric (NIST elliptic curves)
//!   - ES256
//!   - ES384
//! - Asymmetric (RSA)
//!   - RS256
//!   - RS384
//!   - RS512
//!   - PS256
//!   - PS384
//!   - PS512
//! - Asymmetric (`EdDSA`)
//!   - `Ed25519` (aka `EdDSA`)

use std::{borrow::Cow, sync::Arc};

use huskarl_core::{
    Error, ErrorKind,
    crypto::signer::{
        AsymmetricJwsSigner, AsymmetricJwsSignerSelector, JwsSigner, JwsSignerSelector,
    },
    jwk::PublicJwk,
    platform::MaybeSendBoxFuture,
};
use serde::Serialize;
use snafu::prelude::*;
use web_sys::CryptoKey;

use crate::{
    KeyUsage,
    helpers::{
        self, AsymmetricKeyGenParams, GetCryptoError, JsSignError, SignAlgorithm,
        generate_asymmetric_key, get_crypto, get_public_jwk, sign_with_key,
    },
};

#[derive(Debug)]
struct PrivateKeyInner {
    crypto_key: CryptoKey,
    algorithm: GenerateAlgorithm,
    public_jwk: PublicJwk,
}

/// A non-exportable asymmetric private key used to create JWS signatures
/// (ES256/384, RS/PS 256/384/512, Ed25519), implementing [`JwsSigner`] and
/// [`AsymmetricJwsSigner`].
///
/// Generate one with [`generate`](Self::generate). Keys are not extractable by
/// JavaScript; the handle is cheap to clone (`Arc`-backed).
#[derive(Debug, Clone)]
pub struct PrivateKey {
    inner: Arc<PrivateKeyInner>,
}

/// RSA modulus length of 2048 bits (current minimum).
pub const RSA_MODULUS_2048: u32 = 2048;

/// RSA modulus length of 3072 bits (commonly recommended).
pub const RSA_MODULUS_3072: u32 = 3072;

/// RSA modulus length of 4096 bits.
pub const RSA_MODULUS_4096: u32 = 4096;

/// The JWS signature algorithm (and, for RSA, the modulus length) for a
/// generated [`PrivateKey`].
///
/// The RSA variants carry a `modulus_length` in bits: traditionally 2048
/// ([`RSA_MODULUS_2048`]), with 3072 ([`RSA_MODULUS_3072`]) a common
/// recommendation and 4096 ([`RSA_MODULUS_4096`]) where required. Cost grows
/// polynomially with modulus length while the security gain is sub-linear.
#[derive(Debug, Serialize, Clone, Copy)]
pub enum GenerateAlgorithm {
    /// ES256
    Es256,
    /// ES384
    Es384,
    /// RS256
    Rs256 {
        /// Modulus length in bits (see the type-level docs for guidance).
        modulus_length: u32,
    },
    /// RS384
    Rs384 {
        /// Modulus length in bits (see the type-level docs for guidance).
        modulus_length: u32,
    },
    /// RS512
    Rs512 {
        /// Modulus length in bits (see the type-level docs for guidance).
        modulus_length: u32,
    },
    /// PS256
    Ps256 {
        /// Modulus length in bits (see the type-level docs for guidance).
        modulus_length: u32,
    },
    /// PS384
    Ps384 {
        /// Modulus length in bits (see the type-level docs for guidance).
        modulus_length: u32,
    },
    /// PS512
    Ps512 {
        /// Modulus length in bits (see the type-level docs for guidance).
        modulus_length: u32,
    },
    /// `EdDSA` (polymorphic algorithm name)
    EdDsa,
    /// Ed25519 (fully specified algorithm name, ref. RFC 9864)
    Ed25519,
}

impl GenerateAlgorithm {
    fn key_gen_params(&self) -> AsymmetricKeyGenParams<'_> {
        match self {
            GenerateAlgorithm::Es256 => AsymmetricKeyGenParams::Ec {
                name: "ECDSA",
                named_curve: "P-256",
            },
            GenerateAlgorithm::Es384 => AsymmetricKeyGenParams::Ec {
                name: "ECDSA",
                named_curve: "P-384",
            },
            GenerateAlgorithm::Rs256 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSASSA-PKCS1-v1_5",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-256",
            },
            GenerateAlgorithm::Rs384 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSASSA-PKCS1-v1_5",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-384",
            },
            GenerateAlgorithm::Rs512 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSASSA-PKCS1-v1_5",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-512",
            },
            GenerateAlgorithm::Ps256 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSA-PSS",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-256",
            },
            GenerateAlgorithm::Ps384 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSA-PSS",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-384",
            },
            GenerateAlgorithm::Ps512 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSA-PSS",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-512",
            },
            GenerateAlgorithm::EdDsa | GenerateAlgorithm::Ed25519 => {
                AsymmetricKeyGenParams::Ed25519
            }
        }
    }

    fn sign_algorithm(&self) -> SignAlgorithm<'_> {
        match self {
            Self::Es256 => SignAlgorithm::EcDsa {
                name: "ECDSA",
                hash: "SHA-256",
            },
            Self::Es384 => SignAlgorithm::EcDsa {
                name: "ECDSA",
                hash: "SHA-384",
            },
            Self::Rs256 { .. } | Self::Rs384 { .. } | Self::Rs512 { .. } => SignAlgorithm::RsaPkcs1,
            Self::Ps256 { .. } => SignAlgorithm::RsaPss {
                name: "RSA-PSS",
                salt_length: 32,
            },
            Self::Ps384 { .. } => SignAlgorithm::RsaPss {
                name: "RSA-PSS",
                salt_length: 48,
            },
            Self::Ps512 { .. } => SignAlgorithm::RsaPss {
                name: "RSA-PSS",
                salt_length: 64,
            },
            Self::EdDsa | Self::Ed25519 => SignAlgorithm::Ed25519,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Rs256 { .. } => "RS256",
            Self::Rs384 { .. } => "RS384",
            Self::Rs512 { .. } => "RS512",
            Self::Ps256 { .. } => "PS256",
            Self::Ps384 { .. } => "PS384",
            Self::Ps512 { .. } => "PS512",
            Self::EdDsa => "EdDSA",
            Self::Ed25519 => "Ed25519",
        }
    }
}

/// Errors that can occur when generating a private key.
#[derive(Debug, Snafu)]
pub enum GenerateError {
    /// Unable to find webcrypto support in environment.
    #[snafu(display("Failed to find WebCrypto support"))]
    NoCrypto {
        /// The underlying error.
        source: GetCryptoError,
    },
    /// An error occurred when attempting to generate the key.
    #[snafu(display("Error generating key"))]
    Generate {
        /// The underlying error.
        source: helpers::GenerateKeyError,
    },
    /// An error occurred when attempting to get the JWK for the key.
    #[snafu(display("Error getting JWK for private key"))]
    GetPublicJwk {
        /// The underlying error.
        source: helpers::GetPublicJwkError,
    },
}

impl PrivateKey {
    /// Creates a non-extractable private key which can sign material using the
    /// specified JWS algorithm, optionally tagging its public JWK with `kid`.
    ///
    /// # Errors
    ///
    /// Returns [`GenerateError`] if `WebCrypto` is unavailable, key generation
    /// fails, or the public JWK cannot be derived.
    pub async fn generate(
        algorithm: GenerateAlgorithm,
        kid: Option<String>,
    ) -> Result<Self, GenerateError> {
        let crypto = get_crypto().context(NoCryptoSnafu)?;

        // Request both usages: WebCrypto partitions them across the pair, giving
        // the private key `sign` and the public key `verify`. Without `verify`,
        // the exported public JWK carries `key_ops: []` — advertising no
        // capability — and any verifier re-importing it (e.g. from a DPoP proof
        // or JWS `jwk` header) rejects it. See the verifier round-trip tests.
        let key_pair = generate_asymmetric_key(
            &crypto.subtle(),
            algorithm.key_gen_params(),
            &[KeyUsage::Sign, KeyUsage::Verify],
        )
        .await
        .context(GenerateSnafu)?;

        let mut public_jwk = get_public_jwk(&crypto.subtle(), &key_pair.get_public_key())
            .await
            .context(GetPublicJwkSnafu)?;
        public_jwk.kid = kid;

        Ok(Self {
            inner: Arc::new(PrivateKeyInner {
                crypto_key: key_pair.get_private_key(),
                algorithm,
                public_jwk,
            }),
        })
    }
}

/// Errors that can occur when signing.
#[derive(Debug, Snafu)]
pub enum SignError {
    /// Unable to find webcrypto support in environment.
    #[snafu(
        context(name(CryptoAbsentSnafu)),
        display("Failed to find WebCrypto support")
    )]
    NoCrypto {
        /// The underlying error.
        source: GetCryptoError,
    },
    /// Error occurred when attempting to sign.
    #[snafu(display("Signing failed"))]
    Sign {
        /// The underlying error.
        source: JsSignError,
    },
}

impl From<SignError> for Error {
    fn from(value: SignError) -> Self {
        Error::new(ErrorKind::Crypto, value)
    }
}

impl JwsSignerSelector for PrivateKey {
    fn select_signer(&self) -> Arc<dyn JwsSigner> {
        Arc::new(self.clone())
    }
}

impl AsymmetricJwsSignerSelector for PrivateKey {
    fn select_asymmetric_signer(&self) -> Arc<dyn AsymmetricJwsSigner> {
        Arc::new(self.clone())
    }

    fn select_signer_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Arc<dyn AsymmetricJwsSigner>> {
        if self.inner.public_jwk.thumbprint() == thumbprint {
            Some(Arc::new(self.clone()))
        } else {
            None
        }
    }
}

impl AsymmetricJwsSigner for PrivateKey {
    fn public_key_jwk(&self) -> Cow<'_, huskarl_core::jwk::PublicJwk> {
        Cow::Borrowed(&self.inner.public_jwk)
    }
}

impl JwsSigner for PrivateKey {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.inner.algorithm.name())
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner.public_jwk.kid.clone().map(Cow::Owned)
    }

    fn sign<'a>(&'a self, input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            let crypto = get_crypto().context(CryptoAbsentSnafu)?;

            Ok(sign_with_key(
                &crypto.subtle(),
                self.inner.algorithm.sign_algorithm(),
                &self.inner.crypto_key,
                input,
            )
            .await
            .context(SignSnafu)?)
        })
    }
}
