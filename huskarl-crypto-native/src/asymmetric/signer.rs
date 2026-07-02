//! JWS signing with asymmetric private keys (ES256/384, RS/PS 256/384/512,
//! Ed25519), backing huskarl-core's [`JwsSigner`] / [`AsymmetricJwsSigner`]
//! traits.
//!
//! [`PrivateKey`] is the entry type; generate one with [`PrivateKey::generate`]
//! or load one with [`PrivateKey::from_jwk`], [`PrivateKey::load_jwk`],
//! [`PrivateKey::load_pkcs8_pem`], or [`PrivateKey::load_pkcs8_der`].

use std::{borrow::Cow, sync::Arc};

use huskarl_core::{
    Error, ErrorKind,
    crypto::signer::{
        AsymmetricJwsSigner, AsymmetricJwsSignerSelector, JwsSigner, JwsSignerSelector,
    },
    jwk,
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretBytes, SecretString},
};
use pkcs8::DecodePrivateKey;
use rand::Rng;
use rsa::traits::PublicKeyParts as _;
use signature::{SignatureEncoding, Signer as _};
use snafu::prelude::*;

/// Errors that may occur when loading the private key.
#[derive(Debug, Snafu)]
pub enum KeyLoadError {
    /// Failed to access secret information.
    Secret {
        /// The underlying error.
        source: Error,
    },
    /// Failed to decode PKCS#8 key
    #[snafu(display("Failed to decode PKCS#8 key"))]
    KeyDecode {
        /// The underlying error.
        source: pkcs8::Error,
    },
}

/// Errors that may occur when constructing a key from JWK material.
#[derive(Debug, Snafu)]
pub enum JwkError {
    /// The algorithm is unsupported or missing.
    #[snafu(display("Unsupported JWK algorithm: {algorithm:?}"))]
    UnsupportedAlgorithm {
        /// The algorithm field from the JWK, if present.
        algorithm: Option<String>,
    },
    /// The key material is invalid.
    #[snafu(display("Invalid key material"))]
    InvalidKeyMaterial,
    /// The key type does not match the algorithm.
    #[snafu(display("Key type does not match algorithm"))]
    KeyTypeMismatch,
}

/// Errors that may occur when loading a private key from a JWK secret.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum JwkLoadError {
    /// Failed to access secret information.
    Secret {
        /// The underlying error.
        source: Error,
    },
    /// Failed to parse the JWK JSON.
    #[snafu(display("Failed to parse JWK JSON"))]
    JsonParse {
        /// The underlying error.
        source: serde_json::Error,
    },
    /// JWK processing error.
    Jwk {
        /// The underlying error.
        source: JwkError,
    },
}

#[derive(Debug)]
struct PrivateKeyInner {
    signing_key: Key,
    jwk: jwk::PublicJwk,
    thumbprint: String,
    kid: Option<String>,
}

/// An asymmetric private key for JWS signing (ES256/384, RS/PS 256/384/512,
/// Ed25519), implementing [`JwsSigner`] and [`AsymmetricJwsSigner`].
///
/// Generate one with [`generate`](Self::generate), or load one with
/// [`from_jwk`](Self::from_jwk), [`load_jwk`](Self::load_jwk),
/// [`load_pkcs8_pem`](Self::load_pkcs8_pem), or
/// [`load_pkcs8_der`](Self::load_pkcs8_der); cheap to clone (`Arc`-backed).
#[derive(Debug, Clone)]
pub struct PrivateKey {
    inner: Arc<PrivateKeyInner>,
}

#[derive(Debug)]
enum Key {
    Es256(p256::ecdsa::SigningKey),
    Es384(p384::ecdsa::SigningKey),
    Rs256(rsa::pkcs1v15::SigningKey<sha2::Sha256>),
    Rs384(rsa::pkcs1v15::SigningKey<sha2::Sha384>),
    Rs512(rsa::pkcs1v15::SigningKey<sha2::Sha512>),
    Ps256(rsa::pss::SigningKey<sha2::Sha256>),
    Ps384(rsa::pss::SigningKey<sha2::Sha384>),
    Ps512(rsa::pss::SigningKey<sha2::Sha512>),
    Ed25519 {
        key: ed25519_dalek::SigningKey,
        use_fully_specified_jws_algorithm: bool,
    },
}

impl Key {
    pub const fn jws_algorithm(&self) -> &'static str {
        match self {
            Key::Es256(_) => "ES256",
            Key::Es384(_) => "ES384",
            Key::Rs256(_) => "RS256",
            Key::Rs384(_) => "RS384",
            Key::Rs512(_) => "RS512",
            Key::Ps256(_) => "PS256",
            Key::Ps384(_) => "PS384",
            Key::Ps512(_) => "PS512",
            Key::Ed25519 {
                use_fully_specified_jws_algorithm: true,
                ..
            } => "Ed25519",
            Key::Ed25519 {
                use_fully_specified_jws_algorithm: false,
                ..
            } => "EdDSA",
        }
    }

    // The `expect`s below are infallible by construction: an uncompressed SEC1
    // point always carries its x/y coordinates.
    #[allow(clippy::expect_used)]
    pub fn as_public_jwk(&self, kid: Option<&str>) -> jwk::PublicJwk {
        match self {
            Key::Es256(signing_key) => {
                let point = p256::ecdsa::VerifyingKey::from(signing_key).to_sec1_point(false);
                let x = point
                    .x()
                    .expect("uncompressed point always has x coordinate")
                    .to_vec();
                let y = point
                    .y()
                    .expect("uncompressed point always has a y coordinate")
                    .to_vec();

                jwk::PublicJwk::builder()
                    .algorithm(self.jws_algorithm())
                    .maybe_kid(kid)
                    .key_use(jwk::KeyUse::Sign)
                    .key(jwk::EcPublicKey::builder().crv("P-256").x(x).y(y).build())
                    .build()
            }
            Key::Es384(signing_key) => {
                let point = p384::ecdsa::VerifyingKey::from(signing_key).to_sec1_point(false);
                let x = point
                    .x()
                    .expect("uncompressed point always has x coordinate")
                    .to_vec();
                let y = point
                    .y()
                    .expect("uncompressed point always has a y coordinate")
                    .to_vec();

                jwk::PublicJwk::builder()
                    .algorithm(self.jws_algorithm())
                    .maybe_kid(kid)
                    .key_use(jwk::KeyUse::Sign)
                    .key(jwk::EcPublicKey::builder().crv("P-384").x(x).y(y).build())
                    .build()
            }
            Key::Rs256(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Rs384(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Rs512(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Ps256(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Ps384(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Ps512(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Ed25519 { key, .. } => jwk::PublicJwk::builder()
                .algorithm(self.jws_algorithm())
                .maybe_kid(kid)
                .key_use(jwk::KeyUse::Sign)
                .key(
                    jwk::OkpPublicKey::builder()
                        .crv("Ed25519")
                        .x(*key.verifying_key().as_bytes())
                        .build(),
                )
                .build(),
        }
    }

    /// Returns the full private key in JWK format, including private key material.
    ///
    /// The returned value includes the `d` component (and `dp`, `dq`, `p`, `q`, `qi` for RSA)
    /// and must be treated as sensitive.
    // The `expect`s below are infallible by construction: a freshly derived
    // private key always carries its components.
    #[allow(clippy::expect_used)]
    pub fn as_private_jwk(&self, kid: Option<&str>) -> jwk::PrivateJwk {
        use p256::elliptic_curve::PrimeField as _;

        match self {
            Key::Es256(signing_key) => {
                let jwk::PublicKey::Ec(public) = self.as_public_jwk(kid).key else {
                    unreachable!()
                };
                let d = signing_key
                    .as_nonzero_scalar()
                    .to_repr()
                    .as_slice()
                    .to_vec();
                build_private_jwk(
                    jwk::EcKey::builder()
                        .public(public)
                        .d(d)
                        .build()
                        .private_key()
                        .expect("d is set"),
                    self.jws_algorithm(),
                    kid,
                )
            }
            Key::Es384(signing_key) => {
                let jwk::PublicKey::Ec(public) = self.as_public_jwk(kid).key else {
                    unreachable!()
                };
                let d = signing_key
                    .as_nonzero_scalar()
                    .to_repr()
                    .as_slice()
                    .to_vec();
                build_private_jwk(
                    jwk::EcKey::builder()
                        .public(public)
                        .d(d)
                        .build()
                        .private_key()
                        .expect("d is set"),
                    self.jws_algorithm(),
                    kid,
                )
            }
            Key::Rs256(k) => convert_rsa_to_private_jwk(k, kid, self.jws_algorithm()),
            Key::Rs384(k) => convert_rsa_to_private_jwk(k, kid, self.jws_algorithm()),
            Key::Rs512(k) => convert_rsa_to_private_jwk(k, kid, self.jws_algorithm()),
            Key::Ps256(k) => convert_rsa_to_private_jwk(k, kid, self.jws_algorithm()),
            Key::Ps384(k) => convert_rsa_to_private_jwk(k, kid, self.jws_algorithm()),
            Key::Ps512(k) => convert_rsa_to_private_jwk(k, kid, self.jws_algorithm()),
            Key::Ed25519 { key, .. } => {
                let jwk::PublicKey::Okp(public) = self.as_public_jwk(kid).key else {
                    unreachable!()
                };
                let d = key.as_bytes().to_vec();
                build_private_jwk(
                    jwk::OkpKey::builder()
                        .public(public)
                        .d(d)
                        .build()
                        .private_key()
                        .expect("d is set"),
                    self.jws_algorithm(),
                    kid,
                )
            }
        }
    }

    fn from_jwk(key: jwk::PrivateKey, alg: &str) -> Result<Self, JwkError> {
        match key {
            jwk::PrivateKey::Ec(ec) => match (ec.public.crv.as_str(), alg) {
                ("P-256", "ES256") => p256::ecdsa::SigningKey::from_slice(&ec.d)
                    .map(Key::Es256)
                    .map_err(|_| InvalidKeyMaterialSnafu.build()),
                ("P-384", "ES384") => p384::ecdsa::SigningKey::from_slice(&ec.d)
                    .map(Key::Es384)
                    .map_err(|_| InvalidKeyMaterialSnafu.build()),
                _ => KeyTypeMismatchSnafu.fail(),
            },
            jwk::PrivateKey::Rsa(rsa_private) => {
                let n = rsa::BoxedUint::from_be_slice_vartime(&rsa_private.public.n);
                let e = rsa::BoxedUint::from_be_slice_vartime(&rsa_private.public.e);
                let d = rsa::BoxedUint::from_be_slice_vartime(&rsa_private.d);
                let mut primes = Vec::new();
                if let Some(ref p) = rsa_private.p {
                    primes.push(rsa::BoxedUint::from_be_slice_vartime(p));
                }
                if let Some(ref q) = rsa_private.q {
                    primes.push(rsa::BoxedUint::from_be_slice_vartime(q));
                }
                let rsa_key = rsa::RsaPrivateKey::from_components(n, e, d, primes)
                    .map_err(|_| InvalidKeyMaterialSnafu.build())?;
                match alg {
                    "RS256" => Ok(Key::Rs256(rsa::pkcs1v15::SigningKey::new(rsa_key))),
                    "RS384" => Ok(Key::Rs384(rsa::pkcs1v15::SigningKey::new(rsa_key))),
                    "RS512" => Ok(Key::Rs512(rsa::pkcs1v15::SigningKey::new(rsa_key))),
                    "PS256" => Ok(Key::Ps256(rsa::pss::SigningKey::new(rsa_key))),
                    "PS384" => Ok(Key::Ps384(rsa::pss::SigningKey::new(rsa_key))),
                    "PS512" => Ok(Key::Ps512(rsa::pss::SigningKey::new(rsa_key))),
                    _ => KeyTypeMismatchSnafu.fail(),
                }
            }
            jwk::PrivateKey::Okp(okp) => match (okp.public.crv.as_str(), alg) {
                ("Ed25519", "EdDSA") => {
                    let bytes: [u8; 32] = okp
                        .d
                        .as_slice()
                        .try_into()
                        .map_err(|_| InvalidKeyMaterialSnafu.build())?;
                    Ok(Key::Ed25519 {
                        key: ed25519_dalek::SigningKey::from_bytes(&bytes),
                        use_fully_specified_jws_algorithm: false,
                    })
                }
                ("Ed25519", "Ed25519") => {
                    let bytes: [u8; 32] = okp
                        .d
                        .as_slice()
                        .try_into()
                        .map_err(|_| InvalidKeyMaterialSnafu.build())?;
                    Ok(Key::Ed25519 {
                        key: ed25519_dalek::SigningKey::from_bytes(&bytes),
                        use_fully_specified_jws_algorithm: true,
                    })
                }
                _ => KeyTypeMismatchSnafu.fail(),
            },
            _ => KeyTypeMismatchSnafu.fail(),
        }
    }
}

fn build_private_jwk(
    key: impl Into<jwk::PrivateKey>,
    alg: &str,
    kid: Option<&str>,
) -> jwk::PrivateJwk {
    jwk::PrivateJwk::builder()
        .key(key)
        .key_use(jwk::KeyUse::Sign)
        .algorithm(alg)
        .maybe_kid(kid.map(String::from))
        .build()
}

// `private_key()` is infallible here: `d` is set on a real RSA private key.
#[allow(clippy::expect_used)]
fn convert_rsa_to_private_jwk(
    private_key: impl AsRef<rsa::RsaPrivateKey>,
    kid: Option<&str>,
    alg: &str,
) -> jwk::PrivateJwk {
    use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
    let key = private_key.as_ref();
    let public_key = key.to_public_key();
    let primes = key.primes();

    let rsa_key = jwk::RsaKey::builder()
        .public(
            jwk::RsaPublicKey::builder()
                .e(public_key.e().to_be_bytes())
                .n(public_key.n().to_be_bytes())
                .build(),
        )
        .d(key.d().to_be_bytes())
        .maybe_p(primes.first().map(rsa::BoxedUint::to_be_bytes))
        .maybe_q(primes.get(1).map(rsa::BoxedUint::to_be_bytes))
        .maybe_dp(key.dp().map(rsa::BoxedUint::to_be_bytes))
        .maybe_dq(key.dq().map(rsa::BoxedUint::to_be_bytes))
        .maybe_qi(key.qinv().map(|qi| qi.retrieve().to_be_bytes()))
        .build();

    build_private_jwk(rsa_key.private_key().expect("d is set"), alg, kid)
}

fn convert_rsa_public_key_to_jwk(
    private_key: impl AsRef<rsa::RsaPrivateKey>,
    kid: Option<&str>,
    alg: &str,
) -> jwk::PublicJwk {
    let public_key = private_key.as_ref().to_public_key();

    jwk::PublicJwk::builder()
        .algorithm(alg)
        .maybe_kid(kid)
        .key_use(jwk::KeyUse::Sign)
        .key(
            jwk::RsaPublicKey::builder()
                .e(public_key.e().to_be_bytes())
                .n(public_key.n().to_be_bytes())
                .build(),
        )
        .build()
}

/// RSA modulus length of 2048 bits (current minimum).
pub const RSA_MODULUS_2048: u32 = 2048;

/// RSA modulus length of 3072 bits (commonly recommended).
pub const RSA_MODULUS_3072: u32 = 3072;

/// RSA modulus length of 4096 bits.
pub const RSA_MODULUS_4096: u32 = 4096;

/// Asymmetric algorithm for key generation, including RSA key parameters.
///
/// Used with [`PrivateKey::generate`]. For loading existing keys from PKCS#8,
/// use [`AsymmetricAlgorithm`] instead.
///
/// The RSA variants carry a `modulus_length` in bits: traditionally 2048
/// ([`RSA_MODULUS_2048`]), with 3072 ([`RSA_MODULUS_3072`]) a common
/// recommendation and 4096 ([`RSA_MODULUS_4096`]) where required. Cost grows
/// polynomially with modulus length while the security gain is sub-linear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Ed25519, using the algorithm name `EdDSA`
    EdDsa,
    /// Ed25519, using the algorithm name Ed25519
    Ed25519,
}

/// Asymmetric algorithm for signing.
///
/// Used with [`PrivateKey::load_pkcs8_der`] and [`PrivateKey::load_pkcs8_pem`].
/// For generating new keys, use [`GenerateAlgorithm`] with [`PrivateKey::generate`].
// `UPPERCASE` serialization yields the JWA names (`Es256` -> `ES256`); the two
// non-uppercase names (`EdDSA`, `Ed25519`) are spelled out per variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr)]
#[strum(serialize_all = "UPPERCASE")]
pub enum AsymmetricAlgorithm {
    /// ES256
    Es256,
    /// ES384
    Es384,
    /// RS256
    Rs256,
    /// RS384
    Rs384,
    /// RS512
    Rs512,
    /// PS256
    Ps256,
    /// PS384
    Ps384,
    /// PS512
    Ps512,
    /// Ed25519, using the algorithm name `EdDSA`
    #[strum(serialize = "EdDSA")]
    EdDsa,
    /// Ed25519, using the algorithm name Ed25519
    #[strum(serialize = "Ed25519")]
    Ed25519,
}

impl PrivateKey {
    /// Generates an asymmetric key in memory.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if an RSA modulus length below 2048 bits
    /// is requested, and [`ErrorKind::Crypto`] if key generation itself fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
    ///
    /// // Ed25519 takes no parameters; EC and RSA variants are also available
    /// // (RSA carries a modulus length — see `GenerateAlgorithm`).
    /// let signer = PrivateKey::generate(GenerateAlgorithm::Ed25519, Some("key-1".to_string()))?;
    ///
    /// // Publish the public half in a JWKS; the private half stays local and signs.
    /// let public_jwk = signer.as_private_jwk(Some("key-1")).public_jwk();
    /// # Ok::<(), huskarl_core::error::Error>(())
    /// ```
    pub fn generate(key_type: GenerateAlgorithm, kid: Option<String>) -> Result<Self, Error> {
        fn rsa_key(modulus_length: u32) -> Result<rsa::RsaPrivateKey, Error> {
            if modulus_length < RSA_MODULUS_2048 {
                return Err(Error::new(
                    ErrorKind::Config,
                    format!("RSA modulus length must be at least 2048 bits, got {modulus_length}"),
                ));
            }
            rsa::RsaPrivateKey::new(&mut rand::rng(), modulus_length as usize)
                .map_err(|e| Error::new(ErrorKind::Crypto, e).with_context("generating RSA key"))
        }

        let signing_key = match key_type {
            GenerateAlgorithm::Es256 => {
                use p256::elliptic_curve::Generate as _;
                Key::Es256(p256::ecdsa::SigningKey::generate())
            }
            GenerateAlgorithm::Es384 => {
                use p384::elliptic_curve::Generate as _;
                Key::Es384(p384::ecdsa::SigningKey::generate())
            }
            GenerateAlgorithm::Rs256 { modulus_length } => {
                Key::Rs256(rsa::pkcs1v15::SigningKey::new(rsa_key(modulus_length)?))
            }
            GenerateAlgorithm::Rs384 { modulus_length } => {
                Key::Rs384(rsa::pkcs1v15::SigningKey::new(rsa_key(modulus_length)?))
            }
            GenerateAlgorithm::Rs512 { modulus_length } => {
                Key::Rs512(rsa::pkcs1v15::SigningKey::new(rsa_key(modulus_length)?))
            }
            GenerateAlgorithm::Ps256 { modulus_length } => {
                Key::Ps256(rsa::pss::SigningKey::new(rsa_key(modulus_length)?))
            }
            GenerateAlgorithm::Ps384 { modulus_length } => {
                Key::Ps384(rsa::pss::SigningKey::new(rsa_key(modulus_length)?))
            }
            GenerateAlgorithm::Ps512 { modulus_length } => {
                Key::Ps512(rsa::pss::SigningKey::new(rsa_key(modulus_length)?))
            }
            GenerateAlgorithm::EdDsa => {
                let mut secret = [0u8; 32];
                rand::rng().fill_bytes(&mut secret);
                Key::Ed25519 {
                    key: ed25519_dalek::SigningKey::from_bytes(&secret),
                    use_fully_specified_jws_algorithm: false,
                }
            }
            GenerateAlgorithm::Ed25519 => {
                let mut secret = [0u8; 32];
                rand::rng().fill_bytes(&mut secret);
                Key::Ed25519 {
                    key: ed25519_dalek::SigningKey::from_bytes(&secret),
                    use_fully_specified_jws_algorithm: true,
                }
            }
        };

        let jwk = signing_key.as_public_jwk(kid.as_deref());
        let thumbprint = jwk.thumbprint();

        Ok(Self {
            inner: Arc::new(PrivateKeyInner {
                signing_key,
                jwk,
                thumbprint,
                kid,
            }),
        })
    }

    /// Loads the private key from a PKCS#8 DER binary secret.
    ///
    /// # Errors
    ///
    /// Returns [`KeyLoadError::Secret`] if the secret cannot be accessed, or
    /// [`KeyLoadError::KeyDecode`] if it is not a valid PKCS#8 DER key for
    /// `key_type`.
    pub async fn load_pkcs8_der<
        S: Secret<Output = SecretBytes>,
        F: FnOnce(Option<&str>) -> Option<String>,
    >(
        secret: S,
        key_type: AsymmetricAlgorithm,
        key_id_from_secret_identity: F,
    ) -> Result<Self, KeyLoadError> {
        fn build(
            key_id: Option<&str>,
            f: impl Fn() -> Result<Key, pkcs8::Error>,
        ) -> Result<PrivateKey, pkcs8::Error> {
            let signing_key = f()?;
            let jwk = signing_key.as_public_jwk(key_id);
            let thumbprint = jwk.thumbprint();

            Ok(PrivateKey {
                inner: Arc::new(PrivateKeyInner {
                    signing_key,
                    jwk,
                    thumbprint,
                    kid: key_id.map(std::string::ToString::to_string),
                }),
            })
        }

        let secret_output = secret.get_secret_value().await.context(SecretSnafu)?;
        let bytes = secret_output.value.expose_secret();
        let key_id = key_id_from_secret_identity(secret_output.identity.as_deref());

        match key_type {
            AsymmetricAlgorithm::Es256 => build(key_id.as_deref(), || {
                p256::ecdsa::SigningKey::from_pkcs8_der(bytes).map(Key::Es256)
            }),
            AsymmetricAlgorithm::Es384 => build(key_id.as_deref(), || {
                p384::ecdsa::SigningKey::from_pkcs8_der(bytes).map(Key::Es384)
            }),
            AsymmetricAlgorithm::Rs256 => build(key_id.as_deref(), || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_der(bytes).map(Key::Rs256)
            }),
            AsymmetricAlgorithm::Rs384 => build(key_id.as_deref(), || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_der(bytes).map(Key::Rs384)
            }),
            AsymmetricAlgorithm::Rs512 => build(key_id.as_deref(), || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_der(bytes).map(Key::Rs512)
            }),
            AsymmetricAlgorithm::Ps256 => build(key_id.as_deref(), || {
                rsa::pss::SigningKey::from_pkcs8_der(bytes).map(Key::Ps256)
            }),
            AsymmetricAlgorithm::Ps384 => build(key_id.as_deref(), || {
                rsa::pss::SigningKey::from_pkcs8_der(bytes).map(Key::Ps384)
            }),
            AsymmetricAlgorithm::Ps512 => build(key_id.as_deref(), || {
                rsa::pss::SigningKey::from_pkcs8_der(bytes).map(Key::Ps512)
            }),
            AsymmetricAlgorithm::EdDsa => build(key_id.as_deref(), || {
                ed25519_dalek::SigningKey::from_pkcs8_der(bytes).map(|key| Key::Ed25519 {
                    key,
                    use_fully_specified_jws_algorithm: false,
                })
            }),
            AsymmetricAlgorithm::Ed25519 => build(key_id.as_deref(), || {
                ed25519_dalek::SigningKey::from_pkcs8_der(bytes).map(|key| Key::Ed25519 {
                    key,
                    use_fully_specified_jws_algorithm: true,
                })
            }),
        }
        .context(KeyDecodeSnafu)
    }

    /// Loads the private key from a PKCS#8 PEM secret.
    ///
    /// # Errors
    ///
    /// Returns [`KeyLoadError::Secret`] if the secret cannot be accessed, or
    /// [`KeyLoadError::KeyDecode`] if it is not a valid PKCS#8 PEM key for
    /// `key_type`.
    pub async fn load_pkcs8_pem<
        S: Secret<Output = SecretString>,
        F: FnOnce(Option<&str>) -> Option<String>,
    >(
        secret: S,
        key_type: AsymmetricAlgorithm,
        key_id_from_secret_identity: F,
    ) -> Result<Self, KeyLoadError> {
        fn build(
            key_id: Option<&str>,
            f: impl Fn() -> Result<Key, pkcs8::Error>,
        ) -> Result<PrivateKey, pkcs8::Error> {
            let signing_key = f()?;
            let jwk = signing_key.as_public_jwk(key_id);
            let thumbprint = jwk.thumbprint();

            Ok(PrivateKey {
                inner: Arc::new(PrivateKeyInner {
                    signing_key,
                    jwk,
                    thumbprint,
                    kid: key_id.map(std::string::ToString::to_string),
                }),
            })
        }

        let secret_output = secret.get_secret_value().await.context(SecretSnafu)?;
        let bytes = secret_output.value.expose_secret();
        let key_id = key_id_from_secret_identity(secret_output.identity.as_deref());

        match key_type {
            AsymmetricAlgorithm::Es256 => build(key_id.as_deref(), || {
                p256::ecdsa::SigningKey::from_pkcs8_pem(bytes).map(Key::Es256)
            }),
            AsymmetricAlgorithm::Es384 => build(key_id.as_deref(), || {
                p384::ecdsa::SigningKey::from_pkcs8_pem(bytes).map(Key::Es384)
            }),
            AsymmetricAlgorithm::Rs256 => build(key_id.as_deref(), || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_pem(bytes).map(Key::Rs256)
            }),
            AsymmetricAlgorithm::Rs384 => build(key_id.as_deref(), || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_pem(bytes).map(Key::Rs384)
            }),
            AsymmetricAlgorithm::Rs512 => build(key_id.as_deref(), || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_pem(bytes).map(Key::Rs512)
            }),
            AsymmetricAlgorithm::Ps256 => build(key_id.as_deref(), || {
                rsa::pss::SigningKey::from_pkcs8_pem(bytes).map(Key::Ps256)
            }),
            AsymmetricAlgorithm::Ps384 => build(key_id.as_deref(), || {
                rsa::pss::SigningKey::from_pkcs8_pem(bytes).map(Key::Ps384)
            }),
            AsymmetricAlgorithm::Ps512 => build(key_id.as_deref(), || {
                rsa::pss::SigningKey::from_pkcs8_pem(bytes).map(Key::Ps512)
            }),
            AsymmetricAlgorithm::EdDsa => build(key_id.as_deref(), || {
                ed25519_dalek::SigningKey::from_pkcs8_pem(bytes).map(|key| Key::Ed25519 {
                    key,
                    use_fully_specified_jws_algorithm: false,
                })
            }),
            AsymmetricAlgorithm::Ed25519 => build(key_id.as_deref(), || {
                ed25519_dalek::SigningKey::from_pkcs8_pem(bytes).map(|key| Key::Ed25519 {
                    key,
                    use_fully_specified_jws_algorithm: true,
                })
            }),
        }
        .context(KeyDecodeSnafu)
    }

    /// Returns the full private key in JWK format, including the private key
    /// material — the `d` component, plus `dp`, `dq`, `p`, `q`, `qi` for RSA.
    ///
    /// The returned value is sensitive and must be handled accordingly.
    #[must_use]
    pub fn as_private_jwk(&self, kid: Option<&str>) -> jwk::PrivateJwk {
        self.inner.signing_key.as_private_jwk(kid)
    }

    /// Constructs a private key from a [`jwk::PrivateJwk`].
    ///
    /// The JWK must have an `alg` field identifying the signing algorithm.
    /// The `kid` field, if present, is used as the key ID.
    ///
    /// # Errors
    ///
    /// Returns a [`JwkError`] if the JWK is missing an algorithm, has an
    /// unsupported algorithm, or contains invalid key material.
    pub fn from_jwk(private_jwk: jwk::PrivateJwk) -> Result<Self, JwkError> {
        let alg = private_jwk.algorithm.as_deref().ok_or_else(|| {
            UnsupportedAlgorithmSnafu {
                algorithm: None::<String>,
            }
            .build()
        })?;
        let kid = private_jwk.kid;
        let signing_key = Key::from_jwk(private_jwk.key, alg)?;
        let jwk = signing_key.as_public_jwk(kid.as_deref());
        let thumbprint = jwk.thumbprint();

        Ok(Self {
            inner: Arc::new(PrivateKeyInner {
                signing_key,
                jwk,
                thumbprint,
                kid,
            }),
        })
    }

    /// Loads a private key from a JWK JSON secret.
    ///
    /// The secret value must be a JSON string representing a JWK with private
    /// key material (the `d` field). The JWK's `alg` and `kid` fields are used
    /// directly.
    ///
    /// # Errors
    ///
    /// Returns a [`JwkLoadError`] if the secret cannot be accessed, the JSON is
    /// invalid, or the JWK is not a valid private key.
    pub async fn load_jwk<S: Secret<Output = SecretString>>(
        secret: S,
    ) -> Result<Self, JwkLoadError> {
        let secret_output = secret
            .get_secret_value()
            .await
            .context(jwk_load_error::SecretSnafu)?;
        let json = secret_output.value.expose_secret();
        let parsed: jwk::Jwk =
            serde_json::from_str(json).context(jwk_load_error::JsonParseSnafu)?;
        let private_jwk = parsed
            .private_jwk()
            .ok_or(InvalidKeyMaterialSnafu.build())
            .context(jwk_load_error::JwkSnafu)?;
        Self::from_jwk(private_jwk).context(jwk_load_error::JwkSnafu)
    }
}

impl JwsSignerSelector for PrivateKey {
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        let signer: Arc<dyn JwsSigner> = Arc::new(self.clone());
        Box::pin(async move { signer })
    }
}

impl AsymmetricJwsSignerSelector for PrivateKey {
    fn select_asymmetric_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AsymmetricJwsSigner>> {
        let signer: Arc<dyn AsymmetricJwsSigner> = Arc::new(self.clone());
        Box::pin(async move { signer })
    }

    fn select_signer_by_thumbprint<'a>(
        &'a self,
        thumbprint: &'a str,
    ) -> MaybeSendBoxFuture<'a, Option<Arc<dyn AsymmetricJwsSigner>>> {
        let matches = self.inner.thumbprint == thumbprint;
        let signer: Arc<dyn AsymmetricJwsSigner> = Arc::new(self.clone());
        Box::pin(async move { matches.then_some(signer) })
    }
}

impl AsymmetricJwsSigner for PrivateKey {
    fn public_key_jwk(&self) -> Cow<'_, jwk::PublicJwk> {
        Cow::Borrowed(&self.inner.jwk)
    }
}

impl JwsSigner for PrivateKey {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.inner.signing_key.jws_algorithm())
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner.kid.as_deref().map(Cow::Borrowed)
    }

    fn sign<'a>(&'a self, input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            match &self.inner.signing_key {
                Key::Es256(signing_key) => {
                    let signature: p256::ecdsa::Signature = signing_key.sign(input);
                    Ok(signature.to_vec())
                }
                Key::Es384(signing_key) => {
                    let signature: p384::ecdsa::Signature = signing_key.sign(input);
                    Ok(signature.to_vec())
                }
                Key::Rs256(signing_key) => Ok(signing_key.sign(input).to_vec()),
                Key::Rs384(signing_key) => Ok(signing_key.sign(input).to_vec()),
                Key::Rs512(signing_key) => Ok(signing_key.sign(input).to_vec()),
                Key::Ps256(signing_key) => {
                    use rsa::signature::RandomizedSigner;
                    Ok(signing_key.sign_with_rng(&mut rand::rng(), input).to_vec())
                }
                Key::Ps384(signing_key) => {
                    use rsa::signature::RandomizedSigner;
                    Ok(signing_key.sign_with_rng(&mut rand::rng(), input).to_vec())
                }
                Key::Ps512(signing_key) => {
                    use rsa::signature::RandomizedSigner;
                    Ok(signing_key.sign_with_rng(&mut rand::rng(), input).to_vec())
                }
                Key::Ed25519 { key, .. } => Ok(key.sign(input).to_vec()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_rejects_small_rsa_modulus() {
        let error = PrivateKey::generate(
            GenerateAlgorithm::Rs256 {
                modulus_length: 1024,
            },
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Config);
    }

    #[test]
    fn from_jwk_missing_algorithm() {
        let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
        let mut private_jwk = key.as_private_jwk(None);
        private_jwk.algorithm = None;

        let err = PrivateKey::from_jwk(private_jwk).unwrap_err();
        assert!(matches!(err, JwkError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn from_jwk_key_type_mismatch() {
        let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
        let mut private_jwk = key.as_private_jwk(None);
        private_jwk.algorithm = Some("RS256".to_string());

        let err = PrivateKey::from_jwk(private_jwk).unwrap_err();
        assert!(matches!(err, JwkError::KeyTypeMismatch));
    }
}
