//! JWS signing with asymmetric private keys (ES256/384, RS/PS 256/384/512,
//! Ed25519), backing huskarl-core's [`JwsSigner`] / [`AsymmetricJwsSigner`]
//! traits.
//!
//! [`PrivateKey`] is the entry type; generate one with [`PrivateKey::generate`]
//! or load one with [`PrivateKey::from_jwk`] or [`PrivateKey::from_secret`]
//! (composing a decoder such as `JwkJson`, [`Pkcs8Der`], or [`Pkcs8Pem`]).

use std::{borrow::Cow, sync::Arc};

use huskarl_core::{
    Error, ErrorKind,
    crypto::signer::{
        AsymmetricJwsSigner, AsymmetricJwsSignerSelector, JwsSigner, JwsSignerSelector,
    },
    jwk,
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretBytes, SecretMap, SecretString},
};
use pkcs8::DecodePrivateKey;
use rand::Rng;
use rsa::traits::PublicKeyParts as _;
use signature::{SignatureEncoding, Signer as _};

/// The shared key material behind a `PrivateKey` — the signer snapshot the
/// selectors hand out.
#[derive(Debug)]
struct PrivateKeyInner {
    signing_key: Key,
    // `jwk` carries the canonical `kid` (baked in at construction); it is the
    // single source of truth, so `key_id()` and the published JWK can't diverge.
    jwk: jwk::PublicJwk,
    thumbprint: String,
}

/// An asymmetric private key for JWS signing (ES256/384, RS/PS 256/384/512,
/// Ed25519): a [`JwsSignerSelector`] / [`AsymmetricJwsSignerSelector`] whose
/// selection hands out the key's shared inner [`JwsSigner`].
///
/// Generate one with [`generate`](Self::generate), or load one with
/// [`from_jwk`](Self::from_jwk) or [`from_secret`](Self::from_secret) (composing
/// a decoder like `JwkJson`, [`Pkcs8Der`], or [`Pkcs8Pem`]); cheap to clone
/// (`Arc`-backed).
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
    // The `expect`s and `unreachable!`s below are infallible by construction and
    // locally checkable: a freshly derived private key always carries its
    // components, and each arm destructures the public JWK its own `as_public_jwk`
    // arm just built (`Es*` → `Ec`, `Ed25519` → `Okp`). Neither depends on caller
    // input nor on an invariant held at a distance.
    #[allow(clippy::expect_used, clippy::unreachable)]
    pub fn as_private_jwk(&self, kid: Option<&str>) -> jwk::AsymmetricPrivateJwk {
        use p256::elliptic_curve::PrimeField as _;

        match self {
            Key::Es256(signing_key) => {
                let jwk::PublicKey::Ec(public) = self.as_public_jwk(kid).key else {
                    unreachable!("as_public_jwk builds an Ec key for this arm")
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
                    unreachable!("as_public_jwk builds an Ec key for this arm")
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
                    unreachable!("as_public_jwk builds an Okp key for this arm")
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

    fn from_jwk(key: jwk::PrivateKey, alg: &str) -> Result<Self, Error> {
        match key {
            jwk::PrivateKey::Ec(ec) => match (ec.public.crv.as_str(), alg) {
                ("P-256", "ES256") => p256::ecdsa::SigningKey::from_slice(&ec.d)
                    .map(Key::Es256)
                    .map_err(|_| {
                        Error::from(ErrorKind::Config).with_context("invalid JWK key material")
                    }),
                ("P-384", "ES384") => p384::ecdsa::SigningKey::from_slice(&ec.d)
                    .map(Key::Es384)
                    .map_err(|_| {
                        Error::from(ErrorKind::Config).with_context("invalid JWK key material")
                    }),
                _ => Err(Error::from(ErrorKind::Config)
                    .with_context("JWK key type does not match the algorithm")),
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
                let rsa_key =
                    rsa::RsaPrivateKey::from_components(n, e, d, primes).map_err(|_| {
                        Error::from(ErrorKind::Config).with_context("invalid JWK key material")
                    })?;
                match alg {
                    "RS256" => Ok(Key::Rs256(rsa::pkcs1v15::SigningKey::new(rsa_key))),
                    "RS384" => Ok(Key::Rs384(rsa::pkcs1v15::SigningKey::new(rsa_key))),
                    "RS512" => Ok(Key::Rs512(rsa::pkcs1v15::SigningKey::new(rsa_key))),
                    "PS256" => Ok(Key::Ps256(rsa::pss::SigningKey::new(rsa_key))),
                    "PS384" => Ok(Key::Ps384(rsa::pss::SigningKey::new(rsa_key))),
                    "PS512" => Ok(Key::Ps512(rsa::pss::SigningKey::new(rsa_key))),
                    _ => Err(Error::from(ErrorKind::Config)
                        .with_context("JWK key type does not match the algorithm")),
                }
            }
            jwk::PrivateKey::Okp(okp) => match (okp.public.crv.as_str(), alg) {
                ("Ed25519", "EdDSA") => {
                    let bytes: [u8; 32] = okp.d.as_slice().try_into().map_err(|_| {
                        Error::from(ErrorKind::Config).with_context("invalid JWK key material")
                    })?;
                    Ok(Key::Ed25519 {
                        key: ed25519_dalek::SigningKey::from_bytes(&bytes),
                        use_fully_specified_jws_algorithm: false,
                    })
                }
                ("Ed25519", "Ed25519") => {
                    let bytes: [u8; 32] = okp.d.as_slice().try_into().map_err(|_| {
                        Error::from(ErrorKind::Config).with_context("invalid JWK key material")
                    })?;
                    Ok(Key::Ed25519 {
                        key: ed25519_dalek::SigningKey::from_bytes(&bytes),
                        use_fully_specified_jws_algorithm: true,
                    })
                }
                _ => Err(Error::from(ErrorKind::Config)
                    .with_context("JWK key type does not match the algorithm")),
            },
            _ => Err(Error::from(ErrorKind::Config)
                .with_context("JWK key type does not match the algorithm")),
        }
    }
}

fn build_private_jwk(
    key: impl Into<jwk::PrivateKey>,
    alg: &str,
    kid: Option<&str>,
) -> jwk::AsymmetricPrivateJwk {
    jwk::AsymmetricPrivateJwk::builder()
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
) -> jwk::AsymmetricPrivateJwk {
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
/// Used with [`Pkcs8Der`] and [`Pkcs8Pem`].
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
    /// let public_jwk = signer.as_private_jwk().public_jwk();
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

        // The thumbprint (RFC 7638) is over the key material only, so setting
        // `kid` after computing it is immaterial — and taking `kid` by value
        // here (rather than borrowing) keeps the signature `Option<String>`.
        let mut jwk = signing_key.as_public_jwk(None);
        let thumbprint = jwk.thumbprint();
        jwk.kid = kid;

        Ok(Self {
            inner: Arc::new(PrivateKeyInner {
                signing_key,
                jwk,
                thumbprint,
            }),
        })
    }

    /// Returns the full private key in JWK format, including the private key
    /// material — the `d` component, plus `dp`, `dq`, `p`, `q`, `qi` for RSA.
    ///
    /// The JWK carries this key's own `kid` (fixed at construction), so a public
    /// JWK published from it and this key's signatures agree by construction.
    /// The returned value is sensitive and must be handled accordingly.
    #[must_use]
    pub fn as_private_jwk(&self) -> jwk::AsymmetricPrivateJwk {
        self.inner
            .signing_key
            .as_private_jwk(self.inner.jwk.kid.as_deref())
    }

    /// Constructs a private key from a [`jwk::AsymmetricPrivateJwk`].
    ///
    /// The JWK must have an `alg` field identifying the signing algorithm.
    /// The `kid` field, if present, is used as the key ID. Holding a
    /// [`jwk::PrivateJwk`], convert with `try_into()` — the conversion rejects
    /// symmetric keys.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the JWK is missing its algorithm, uses an
    /// unsupported one, or contains invalid key material.
    pub fn from_jwk(private_jwk: jwk::AsymmetricPrivateJwk) -> Result<Self, Error> {
        let alg = private_jwk.algorithm.as_deref().ok_or_else(|| {
            Error::from(ErrorKind::Config)
                .with_context("JWK is missing the alg field identifying the signing algorithm")
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
            }),
        })
    }

    /// Finalizes a private key from a secret that yields a [`jwk::PrivateJwk`].
    ///
    /// The single loading funnel: compose a decoder onto your secret to reach a
    /// `Secret<Output = PrivateJwk>` — `secret.mapped(Pkcs8Der::new(alg))` for a
    /// PKCS#8 secret, or [`jwk::JwkJson`] for the blessed path — and this
    /// resolves it into a usable signer on any backend.
    ///
    /// The key ID follows a clear precedence: an explicit `kid` in the JWK wins;
    /// otherwise the secret's `identity` (e.g. a secret-manager version name)
    /// fills it; otherwise there is none.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the secret cannot be fetched or decoded,
    /// if the JWK is symmetric (`oct`) rather than an asymmetric private key,
    /// or if it is not a valid signing key.
    pub async fn from_secret<S: Secret<Output = jwk::PrivateJwk>>(
        secret: S,
    ) -> Result<Self, Error> {
        let output = secret.get_secret_value().await?;
        // Explicit JWK kid > secret identity > none.
        let private_jwk = output.value.with_kid_fallback(output.identity);
        Self::from_jwk(private_jwk.try_into()?)
    }
}

/// Parses PKCS#8 DER bytes into a signing key of the given algorithm.
///
/// Backend-internal helper behind the [`pkcs8_der`] conversion, keeping the
/// per-algorithm decoding in one place.
fn key_from_pkcs8_der(der: &[u8], key_type: AsymmetricAlgorithm) -> Result<Key, pkcs8::Error> {
    match key_type {
        AsymmetricAlgorithm::Es256 => p256::ecdsa::SigningKey::from_pkcs8_der(der).map(Key::Es256),
        AsymmetricAlgorithm::Es384 => p384::ecdsa::SigningKey::from_pkcs8_der(der).map(Key::Es384),
        AsymmetricAlgorithm::Rs256 => {
            rsa::pkcs1v15::SigningKey::from_pkcs8_der(der).map(Key::Rs256)
        }
        AsymmetricAlgorithm::Rs384 => {
            rsa::pkcs1v15::SigningKey::from_pkcs8_der(der).map(Key::Rs384)
        }
        AsymmetricAlgorithm::Rs512 => {
            rsa::pkcs1v15::SigningKey::from_pkcs8_der(der).map(Key::Rs512)
        }
        AsymmetricAlgorithm::Ps256 => rsa::pss::SigningKey::from_pkcs8_der(der).map(Key::Ps256),
        AsymmetricAlgorithm::Ps384 => rsa::pss::SigningKey::from_pkcs8_der(der).map(Key::Ps384),
        AsymmetricAlgorithm::Ps512 => rsa::pss::SigningKey::from_pkcs8_der(der).map(Key::Ps512),
        AsymmetricAlgorithm::EdDsa => {
            ed25519_dalek::SigningKey::from_pkcs8_der(der).map(|key| Key::Ed25519 {
                key,
                use_fully_specified_jws_algorithm: false,
            })
        }
        AsymmetricAlgorithm::Ed25519 => {
            ed25519_dalek::SigningKey::from_pkcs8_der(der).map(|key| Key::Ed25519 {
                key,
                use_fully_specified_jws_algorithm: true,
            })
        }
    }
}

/// Converts a PKCS#8 DER private key into a complete
/// [`jwk::AsymmetricPrivateJwk`], deriving the public half from the private
/// material and stamping `kid`.
///
/// This is the one crypto-bearing step in loading a non-JWK key: the result is
/// a self-describing JWK (`alg` from `algorithm`, public coordinates recomputed
/// — so Ed25519 seeds and public-less EC keys work too) that
/// [`PrivateKey::from_jwk`], on any backend, can finalize. PEM input is the same
/// conversion behind a text unwrap; a JWK secret skips it entirely.
///
/// # Errors
///
/// Returns [`ErrorKind::Config`] if `der` is not a valid PKCS#8 DER key for
/// `algorithm`.
pub fn pkcs8_der(
    der: &[u8],
    algorithm: AsymmetricAlgorithm,
    kid: Option<&str>,
) -> Result<jwk::AsymmetricPrivateJwk, Error> {
    let signing_key = key_from_pkcs8_der(der, algorithm).map_err(|source| {
        Error::new(ErrorKind::Config, source).with_context("decoding PKCS#8 DER private key")
    })?;
    Ok(signing_key.as_private_jwk(kid))
}

/// A [`SecretMap`] that decodes a PKCS#8 DER secret into a [`jwk::PrivateJwk`].
///
/// Compose it onto any byte secret — `secret.mapped(Pkcs8Der::new(alg))` — to
/// get a `Secret<Output = PrivateJwk>` for the JWK loading funnel. PKCS#8
/// carries no key ID, so [`with_kid`](Self::with_kid) stamps one onto the
/// produced JWK.
#[derive(Debug, Clone)]
pub struct Pkcs8Der {
    algorithm: AsymmetricAlgorithm,
    kid: Option<String>,
}

impl Pkcs8Der {
    /// Decodes a PKCS#8 DER key of the given algorithm, with no key ID.
    #[must_use]
    pub fn new(algorithm: AsymmetricAlgorithm) -> Self {
        Self {
            algorithm,
            kid: None,
        }
    }

    /// Stamps `kid` onto the produced JWK.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }
}

impl SecretMap for Pkcs8Der {
    type In = SecretBytes;
    type Out = jwk::PrivateJwk;

    fn apply(&self, input: SecretBytes) -> Result<jwk::PrivateJwk, Error> {
        pkcs8_der(input.expose_secret(), self.algorithm, self.kid.as_deref()).map(Into::into)
    }
}

/// Converts a PKCS#8 PEM private key into a complete
/// [`jwk::AsymmetricPrivateJwk`].
///
/// PEM is just armored DER, so this unwraps the text envelope and defers to
/// [`pkcs8_der`] — identical public-key derivation, `kid` stamping, and error
/// folding, no separate per-algorithm decode.
///
/// # Errors
///
/// Returns [`ErrorKind::Config`] if `pem` is not a valid PKCS#8 PEM key for
/// `algorithm`.
pub fn pkcs8_pem(
    pem: &str,
    algorithm: AsymmetricAlgorithm,
    kid: Option<&str>,
) -> Result<jwk::AsymmetricPrivateJwk, Error> {
    let (_label, document) = pkcs8::SecretDocument::from_pem(pem).map_err(|source| {
        Error::new(ErrorKind::Config, source).with_context("decoding PKCS#8 PEM private key")
    })?;
    pkcs8_der(document.as_bytes(), algorithm, kid)
}

/// A [`SecretMap`] that decodes a PKCS#8 PEM secret into a [`jwk::PrivateJwk`].
///
/// The text counterpart of [`Pkcs8Der`]: `secret.mapped(Pkcs8Pem::new(alg))`.
/// Like the DER form it needs the algorithm (PKCS#8 does not disambiguate the
/// RSA signing schemes) and takes an optional [`with_kid`](Self::with_kid),
/// since PEM carries no key ID.
#[derive(Debug, Clone)]
pub struct Pkcs8Pem {
    algorithm: AsymmetricAlgorithm,
    kid: Option<String>,
}

impl Pkcs8Pem {
    /// Decodes a PKCS#8 PEM key of the given algorithm, with no key ID.
    #[must_use]
    pub fn new(algorithm: AsymmetricAlgorithm) -> Self {
        Self {
            algorithm,
            kid: None,
        }
    }

    /// Stamps `kid` onto the produced JWK.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }
}

impl SecretMap for Pkcs8Pem {
    type In = SecretString;
    type Out = jwk::PrivateJwk;

    fn apply(&self, input: SecretString) -> Result<jwk::PrivateJwk, Error> {
        pkcs8_pem(input.expose_secret(), self.algorithm, self.kid.as_deref()).map(Into::into)
    }
}

impl JwsSignerSelector for PrivateKey {
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        let snapshot: Arc<dyn JwsSigner> = self.inner.clone();
        Box::pin(async move { snapshot })
    }
}

impl AsymmetricJwsSignerSelector for PrivateKey {
    fn select_asymmetric_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AsymmetricJwsSigner>> {
        let snapshot: Arc<dyn AsymmetricJwsSigner> = self.inner.clone();
        Box::pin(async move { snapshot })
    }

    fn select_signer_by_thumbprint<'a>(
        &'a self,
        thumbprint: &'a str,
    ) -> MaybeSendBoxFuture<'a, Option<Arc<dyn AsymmetricJwsSigner>>> {
        let snapshot = (self.inner.thumbprint == thumbprint)
            .then(|| self.inner.clone() as Arc<dyn AsymmetricJwsSigner>);
        Box::pin(async move { snapshot })
    }
}

impl AsymmetricJwsSigner for PrivateKeyInner {
    fn public_key_jwk(&self) -> Cow<'_, jwk::PublicJwk> {
        Cow::Borrowed(&self.jwk)
    }
}

impl JwsSigner for PrivateKeyInner {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.signing_key.jws_algorithm())
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.jwk.kid.as_deref().map(Cow::Borrowed)
    }

    fn sign<'a>(&'a self, input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        // The panicking `Signer::sign` wrappers are off limits here: the load
        // paths accept keys that `generate` would refuse (e.g. an undersized
        // legacy RSA modulus the PSS/PKCS#1 encoding doesn't fit), so signing
        // can genuinely fail and must surface as an `Err`.
        fn crypto_error(e: impl std::error::Error + Send + Sync + 'static) -> Error {
            Error::new(ErrorKind::Crypto, e).with_context("signing JWS input")
        }

        Box::pin(async move {
            match &self.signing_key {
                Key::Es256(signing_key) => {
                    let signature: p256::ecdsa::Signature =
                        signing_key.try_sign(input).map_err(crypto_error)?;
                    Ok(signature.to_vec())
                }
                Key::Es384(signing_key) => {
                    let signature: p384::ecdsa::Signature =
                        signing_key.try_sign(input).map_err(crypto_error)?;
                    Ok(signature.to_vec())
                }
                Key::Rs256(signing_key) => {
                    Ok(signing_key.try_sign(input).map_err(crypto_error)?.to_vec())
                }
                Key::Rs384(signing_key) => {
                    Ok(signing_key.try_sign(input).map_err(crypto_error)?.to_vec())
                }
                Key::Rs512(signing_key) => {
                    Ok(signing_key.try_sign(input).map_err(crypto_error)?.to_vec())
                }
                Key::Ps256(signing_key) => {
                    use rsa::signature::RandomizedSigner;
                    Ok(signing_key
                        .try_sign_with_rng(&mut rand::rng(), input)
                        .map_err(crypto_error)?
                        .to_vec())
                }
                Key::Ps384(signing_key) => {
                    use rsa::signature::RandomizedSigner;
                    Ok(signing_key
                        .try_sign_with_rng(&mut rand::rng(), input)
                        .map_err(crypto_error)?
                        .to_vec())
                }
                Key::Ps512(signing_key) => {
                    use rsa::signature::RandomizedSigner;
                    Ok(signing_key
                        .try_sign_with_rng(&mut rand::rng(), input)
                        .map_err(crypto_error)?
                        .to_vec())
                }
                Key::Ed25519 { key, .. } => Ok(key.try_sign(input).map_err(crypto_error)?.to_vec()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pkcs8_der_yields_a_complete_signing_jwk_with_the_requested_kid() {
        use p256::{ecdsa::signature::Verifier as _, elliptic_curve::Generate as _};
        use pkcs8::EncodePrivateKey as _;

        // A key we control, exported to PKCS#8 DER — the "raw" secret payload.
        let source = p256::ecdsa::SigningKey::generate();
        let der = source.to_pkcs8_der().unwrap();

        // Convert via the new path and stamp a kid (PKCS#8 carries none).
        let private_jwk =
            pkcs8_der(der.as_bytes(), AsymmetricAlgorithm::Es256, Some("key-1")).unwrap();
        assert_eq!(private_jwk.kid.as_deref(), Some("key-1"));
        assert_eq!(private_jwk.algorithm.as_deref(), Some("ES256"));

        // It finalizes into a usable signer whose published kid can't diverge
        // from key_id() — single source of truth.
        let key = PrivateKey::from_jwk(private_jwk).unwrap();
        let signer = key.select_asymmetric_signer().await;
        assert_eq!(signer.key_id().as_deref(), Some("key-1"));
        assert_eq!(signer.public_key_jwk().kid.as_deref(), Some("key-1"));

        // Gold standard: a signature from the converted key verifies under the
        // ORIGINAL key's public half, proving the DER round-tripped to the same
        // private material.
        let signature_bytes = signer.sign(b"payload").await.unwrap();
        let signature = p256::ecdsa::Signature::from_slice(&signature_bytes).unwrap();
        let verifying_key = p256::ecdsa::VerifyingKey::from(&source);
        verifying_key.verify(b"payload", &signature).unwrap();
    }

    #[tokio::test]
    async fn pkcs8_der_carries_the_fully_specified_ed25519_algorithm_into_the_jwk() {
        use pkcs8::EncodePrivateKey as _;
        use rand::Rng as _;

        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let source = ed25519_dalek::SigningKey::from_bytes(&seed);
        let der = source.to_pkcs8_der().unwrap();

        // `Ed25519` selects the fully-specified JWS name; `EdDsa` would select
        // the classic `EdDSA`. That choice is not separate state — it lands in
        // the JWK's `alg` and round-trips back through the funnel.
        let jwk = pkcs8_der(der.as_bytes(), AsymmetricAlgorithm::Ed25519, Some("ed")).unwrap();
        assert_eq!(jwk.algorithm.as_deref(), Some("Ed25519"));

        let key = PrivateKey::from_jwk(jwk).unwrap();
        assert_eq!(
            key.select_signer().await.jws_algorithm().as_ref(),
            "Ed25519"
        );

        // And the classic spelling survives the same trip.
        let classic = pkcs8_der(der.as_bytes(), AsymmetricAlgorithm::EdDsa, None).unwrap();
        assert_eq!(classic.algorithm.as_deref(), Some("EdDSA"));
    }

    #[tokio::test]
    async fn from_secret_fills_kid_from_identity_then_prefers_an_explicit_jwk_kid() {
        use huskarl_core::secrets::{ProvidedSecret, Secret as _, SecretBytes, WithIdentity};
        use p256::elliptic_curve::Generate as _;
        use pkcs8::EncodePrivateKey as _;

        let source = p256::ecdsa::SigningKey::generate();
        let der = source.to_pkcs8_der().unwrap().as_bytes().to_vec();

        // PKCS#8 carries no kid, so the secret's identity fills it.
        let secret = WithIdentity::new(
            ProvidedSecret::new(SecretBytes::new(der.clone())),
            "version-42",
        )
        .mapped(Pkcs8Der::new(AsymmetricAlgorithm::Es256));
        let key = PrivateKey::from_secret(secret).await.unwrap();
        let signer = key.select_signer().await;
        assert_eq!(signer.key_id().as_deref(), Some("version-42"));

        // An explicit kid stamped onto the JWK wins over the identity.
        let secret = WithIdentity::new(ProvidedSecret::new(SecretBytes::new(der)), "version-42")
            .mapped(Pkcs8Der::new(AsymmetricAlgorithm::Es256).with_kid("explicit"));
        let key = PrivateKey::from_secret(secret).await.unwrap();
        let signer = key.select_signer().await;
        assert_eq!(signer.key_id().as_deref(), Some("explicit"));
    }

    #[tokio::test]
    async fn from_secret_loads_a_jwk_json_secret_with_no_alg_or_kid_arguments() {
        use huskarl_core::{
            jwk::JwkJson,
            secrets::{ProvidedSecret, Secret as _, SecretString},
        };

        // A self-describing JWK (its own alg + kid) stored as JSON. Loading
        // needs no algorithm or key-id argument at all.
        const PRIVATE_JWK: &str = r#"{
            "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "in-the-jwk",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
        }"#;

        let key = PrivateKey::from_secret(
            ProvidedSecret::new(SecretString::new(PRIVATE_JWK)).mapped(JwkJson),
        )
        .await
        .unwrap();

        let signer = key.select_signer().await;
        assert_eq!(signer.key_id().as_deref(), Some("in-the-jwk"));
        assert_eq!(signer.jws_algorithm().as_ref(), "ES256");
    }

    #[test]
    fn pkcs8_pem_unwraps_to_the_same_jwk_as_the_der_path() {
        use p256::elliptic_curve::Generate as _;
        use pkcs8::{EncodePrivateKey as _, LineEnding};

        let source = p256::ecdsa::SigningKey::generate();
        let pem = source.to_pkcs8_pem(LineEnding::LF).unwrap();
        let der = source.to_pkcs8_der().unwrap();

        let via_pem = pkcs8_pem(&pem, AsymmetricAlgorithm::Es256, Some("pem-key")).unwrap();
        let via_der =
            pkcs8_der(der.as_bytes(), AsymmetricAlgorithm::Es256, Some("pem-key")).unwrap();

        assert_eq!(via_pem.kid.as_deref(), Some("pem-key"));
        assert_eq!(via_pem.algorithm.as_deref(), Some("ES256"));
        // PEM is just armored DER — both paths produce the identical JWK.
        assert_eq!(via_pem, via_der);
    }

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

    #[tokio::test]
    async fn sign_with_undersized_rsa_key_errors_instead_of_panicking() {
        // The load paths (unlike `generate`) accept legacy RSA keys below
        // 2048 bits, and PS512's PSS encoding (two 64-byte digests + 2) does
        // not fit a 1024-bit modulus — signing must fail as an error.
        let rsa_key = rsa::RsaPrivateKey::new(&mut rand::rng(), 1024).unwrap();
        let signing_key = Key::Ps512(rsa::pss::SigningKey::new(rsa_key));
        let jwk = signing_key.as_public_jwk(None);
        let thumbprint = jwk.thumbprint();
        let key = PrivateKey {
            inner: Arc::new(PrivateKeyInner {
                signing_key,
                jwk,
                thumbprint,
            }),
        };

        let error = key
            .select_signer()
            .await
            .sign(b"payload")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Crypto);
    }

    #[test]
    fn from_jwk_missing_algorithm() {
        let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
        let mut private_jwk = key.as_private_jwk();
        private_jwk.algorithm = None;

        let err = PrivateKey::from_jwk(private_jwk).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    #[test]
    fn from_jwk_key_type_mismatch() {
        let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
        let mut private_jwk = key.as_private_jwk();
        private_jwk.algorithm = Some("RS256".to_string());

        let err = PrivateKey::from_jwk(private_jwk).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }
}
