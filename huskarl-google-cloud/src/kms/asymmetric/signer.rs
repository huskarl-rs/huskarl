//! Signing with asymmetric Cloud KMS keys.

use std::{borrow::Cow, sync::Arc};

use bon::bon;
use der::Decode as _;
use google_cloud_kms_v1::{
    client::KeyManagementService, model::crypto_key_version::CryptoKeyVersionAlgorithm,
};
use huskarl_core::{
    RetryAdvice,
    crypto::signer::{
        AsymmetricJwsSigner, AsymmetricJwsSignerSelector, JwsSigner, JwsSignerSelector,
    },
    jwk::{self, PublicJwk},
    platform::MaybeSendBoxFuture,
};
use p256::{
    ecdsa::signature,
    elliptic_curve::{pkcs8::DecodePublicKey as _, sec1::ToSec1Point as _},
};
use snafu::prelude::*;

use super::super::version::VersionStrategy;
use crate::kid::VersionKid;

/// An error returned while building an asymmetric signing key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SetupError {
    /// Failed to resolve the key version.
    VersionResolution {
        /// The underlying version resolution error.
        source: super::super::version::VersionResolutionError,
    },
    /// The specified key uses an unsupported algorithm.
    UnsupportedAlgorithm {
        /// The algorithm reported by the KMS API.
        algorithm: CryptoKeyVersionAlgorithm,
    },
    /// The name reported by KMS did not follow the required format.
    InvalidKeyVersionName,
    /// Failed to retrieve the public key from KMS.
    GetPublicKey {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// The public key PEM could not be parsed into a JWK.
    PublicKeyParse {
        /// The underlying parse error.
        source: PublicKeyParseError,
    },
    /// Failed to list crypto key versions.
    ListCryptoKeyVersions {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// No enabled crypto key versions were found.
    NoEnabledCryptoKeyVersions,
    /// The resolved primary version was not found among the enabled versions.
    PrimaryVersionNotFound,
}

impl SetupError {
    /// Returns advice about retrying the failed operation.
    ///
    /// If the service supplied a minimum delay in the RPC's `RetryInfo` detail,
    /// the returned [`RetryAdvice`] preserves it.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            SetupError::VersionResolution { source } => source.retry_advice(),
            SetupError::GetPublicKey { source } | SetupError::ListCryptoKeyVersions { source } => {
                crate::retry::advice(source)
            }
            SetupError::UnsupportedAlgorithm { .. }
            | SetupError::InvalidKeyVersionName
            | SetupError::PublicKeyParse { .. }
            | SetupError::NoEnabledCryptoKeyVersions
            | SetupError::PrimaryVersionNotFound => RetryAdvice::No,
        }
    }

    /// Returns `true` if retrying the failed operation may help.
    ///
    /// This is a coarse view of [`retry_advice`](Self::retry_advice) that
    /// discards any minimum retry delay supplied by the service.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        !matches!(self.retry_advice(), RetryAdvice::No)
    }
}

impl From<SetupError> for huskarl_core::Error {
    #[track_caller]
    fn from(err: SetupError) -> Self {
        huskarl_core::Error::new(err.retry_advice(), err)
    }
}

/// An error returned while parsing a PEM-encoded public key into a JWK.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PublicKeyParseError {
    /// The PEM document could not be decoded.
    PemDecode {
        /// The underlying PEM decoding error.
        source: pem_rfc7468::Error,
    },
    /// The PEM-encoded EC public key could not be decoded.
    #[snafu(display("failed to decode {algorithm} public key PEM"))]
    EcDecode {
        /// The JWS algorithm of the key.
        algorithm: &'static str,
        /// The underlying SPKI error.
        source: spki::Error,
    },
    /// The DER-encoded SPKI structure could not be parsed.
    SpkiParse {
        /// The underlying DER decoding error.
        source: der::Error,
    },
    /// The RSA public key's ASN.1 structure could not be parsed.
    RsaParse {
        /// The underlying DER decoding error.
        source: der::Error,
    },
    /// The Ed25519 public key has an unexpected length.
    #[snafu(display("Ed25519 public key is {length} bytes, expected 32"))]
    Ed25519Length {
        /// The actual length of the key bytes.
        length: usize,
    },
    /// An EC point coordinate is missing from the public key.
    #[snafu(display("missing {algorithm} point coordinate"))]
    MissingCoordinate {
        /// The JWS algorithm of the key.
        algorithm: &'static str,
    },
    /// The JWK thumbprint could not be computed.
    Thumbprint,
    /// No public-key parser is available for the given algorithm.
    #[snafu(display("no public key parser for algorithm {algorithm}"))]
    UnsupportedParseAlgorithm {
        /// The algorithm that was not supported.
        algorithm: String,
    },
}

/// An error returned while signing with an asymmetric KMS key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SigningError {
    /// Failed to sign data with the key.
    AsymmetricSign {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// Failed to convert ECDSA signature from DER to fixed format.
    SignatureConversion {
        /// Description of the conversion error.
        source: signature::Error,
    },
    /// The response named a different key version from the request.
    ///
    /// The signature is discarded because it cannot be attributed to the
    /// requested version.
    MismatchedKeyInfo,
}

impl SigningError {
    /// Returns advice about retrying the failed operation.
    ///
    /// If the service supplied a minimum delay in the RPC's `RetryInfo` detail,
    /// the returned [`RetryAdvice`] preserves it.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            SigningError::AsymmetricSign { source } => crate::retry::advice(source),
            SigningError::SignatureConversion { .. } | SigningError::MismatchedKeyInfo => {
                RetryAdvice::No
            }
        }
    }

    /// Returns `true` if retrying the failed operation may help.
    ///
    /// This is a coarse view of [`retry_advice`](Self::retry_advice) that
    /// discards any minimum retry delay supplied by the service.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        !matches!(self.retry_advice(), RetryAdvice::No)
    }
}

impl From<SigningError> for huskarl_core::Error {
    #[track_caller]
    fn from(err: SigningError) -> Self {
        huskarl_core::Error::new(err.retry_advice(), err)
    }
}

// ─── KeyVersion ──────────────────────────────────────────────────────────────

/// A signing key bound to a specific Cloud KMS key version.
///
/// This is the lowest-level signing primitive: it holds a reference to a
/// specific `CryptoKeyVersion` resource and delegates all signing operations
/// to Cloud KMS.
///
/// This type implements [`JwsSigner`], [`JwsSignerSelector`] (selecting itself),
/// [`AsymmetricJwsSigner`], and [`AsymmetricJwsSignerSelector`].
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::asymmetric::signer::KeyVersion;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = KeyVersion::builder()
///     .resource_name("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
///     .kms_client(kms_client)
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct KeyVersion {
    /// The KMS client used for operations.
    kms_client: KeyManagementService,
    /// The full resource name of the key version.
    resource_name: String,
    /// The JWS algorithm identifier (for example, `"ES256"` or `"PS256"`).
    jws_algorithm: String,
    /// The key ID for the JWT `kid` header, if configured.
    key_id: Option<String>,
    /// The public key JWK.
    public_key_jwk: PublicJwk,
    /// The JWK thumbprint (RFC 7638).
    thumbprint: String,
}

#[bon]
impl KeyVersion {
    /// Creates a `KeyVersion` from a Cloud KMS key version resource name.
    ///
    /// Fetches the public key and algorithm metadata from KMS.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key could not be retrieved,
    /// the algorithm is not supported, or the public key PEM could not
    /// be parsed into a JWK.
    #[builder(finish_fn = build)]
    pub async fn builder(
        /// The full resource name of the crypto key version.
        #[builder(into)]
        resource_name: String,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// Use the fully-specified JWS algorithm identifier for `EdDSA` keys.
        ///
        /// When `true` (the default), Ed25519 keys advertise `"Ed25519"` as
        /// the JWS algorithm per [RFC 9864]. When `false`, the deprecated
        /// polymorphic `"EdDSA"` identifier is used instead.
        ///
        /// This only affects signing; it has no effect on other algorithms.
        ///
        /// [RFC 9864]: https://www.rfc-editor.org/rfc/rfc9864
        #[builder(default = true)]
        use_fully_specified_jws_algorithm: bool,
        /// The policy for deriving a `kid` from the key version ID. Defaults to
        /// [`VersionKid::none()`] (no `kid`).
        #[builder(default = VersionKid::none())]
        kid: VersionKid,
    ) -> Result<Self, SetupError> {
        build_key_version(
            resource_name,
            kms_client,
            use_fully_specified_jws_algorithm,
            kid,
        )
        .await
    }
}

impl JwsSignerSelector for KeyVersion {
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        let signer: Arc<dyn JwsSigner> = Arc::new(self.clone());
        Box::pin(async move { signer })
    }
}

impl JwsSigner for KeyVersion {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.jws_algorithm)
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.key_id.as_deref().map(Cow::Borrowed)
    }

    fn sign<'a>(
        &'a self,
        input: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, huskarl_core::Error>> {
        Box::pin(async move {
            let response = self
                .kms_client
                .asymmetric_sign()
                .set_name(&self.resource_name)
                .set_data(input.to_vec())
                .send()
                .await
                .context(AsymmetricSignSnafu)?;

            // Verify the response came from the expected key version.
            if response.name != self.resource_name {
                return Err(SigningError::MismatchedKeyInfo.into());
            }

            let signature = response.signature.to_vec();

            // For ECDSA, KMS returns DER-encoded signatures but JWT needs
            // fixed-size IEEE P1363 format (r || s).
            let signature = match self.jws_algorithm.as_str() {
                "ES256" => convert_ecdsa_der_to_fixed(&signature, EcDsaVariant::P256)
                    .context(SignatureConversionSnafu)?,
                "ES384" => convert_ecdsa_der_to_fixed(&signature, EcDsaVariant::P384)
                    .context(SignatureConversionSnafu)?,
                _ => signature,
            };

            Ok(signature)
        })
    }
}

impl AsymmetricJwsSignerSelector for KeyVersion {
    fn select_asymmetric_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AsymmetricJwsSigner>> {
        let signer: Arc<dyn AsymmetricJwsSigner> = Arc::new(self.clone());
        Box::pin(async move { signer })
    }

    fn select_signer_by_thumbprint<'a>(
        &'a self,
        thumbprint: &'a str,
    ) -> MaybeSendBoxFuture<'a, Option<Arc<dyn AsymmetricJwsSigner>>> {
        let signer: Option<Arc<dyn AsymmetricJwsSigner>> = if self.thumbprint == thumbprint {
            Some(Arc::new(self.clone()))
        } else {
            None
        };
        Box::pin(async move { signer })
    }
}

impl AsymmetricJwsSigner for KeyVersion {
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
        Cow::Borrowed(&self.public_key_jwk)
    }
}

// ─── SigningKey ─────────────────────────────────────────────────────────────────────

/// A signing key backed by a Cloud KMS `CryptoKey`.
///
/// Resolves a primary key version using the configured [`VersionStrategy`]
/// and loads all enabled signing-capable versions. The primary version is
/// used for signing via [`JwsSignerSelector::select_signer`], while all
/// enabled versions are available for thumbprint-based selection via
/// [`AsymmetricJwsSignerSelector::select_signer_by_thumbprint`].
///
/// # Examples
///
/// ## Latest version (default)
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::asymmetric::signer::SigningKey;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = SigningKey::builder()
///     .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///     .kms_client(kms_client)
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// ## By label
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::{VersionStrategy, asymmetric::signer::SigningKey};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = SigningKey::builder()
///     .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///     .kms_client(kms_client)
///     .strategy(VersionStrategy::ByLabel("active_version".into()))
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SigningKey {
    primary: KeyVersion,
    additional: Vec<KeyVersion>,
}

#[bon]
impl SigningKey {
    /// Creates a `SigningKey` from a Cloud KMS crypto key resource name.
    ///
    /// Resolves the primary version using the configured strategy and loads
    /// all enabled signing-capable versions. The primary is used for
    /// [`select_signer`](JwsSignerSelector::select_signer), while all
    /// versions are searchable by thumbprint via
    /// [`select_signer_by_thumbprint`](AsymmetricJwsSignerSelector::select_signer_by_thumbprint).
    ///
    /// # Errors
    ///
    /// Returns an error if the version could not be resolved, the public key
    /// could not be retrieved, the algorithm is not supported, or the primary
    /// version is not among the enabled versions.
    #[builder(finish_fn = build)]
    pub async fn builder(
        /// The full resource name of the crypto key.
        #[builder(into)]
        key_name: String,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// The version selection strategy. Defaults to [`VersionStrategy::Latest`].
        #[builder(default)]
        strategy: VersionStrategy,
        /// Use the fully-specified JWS algorithm identifier for `EdDSA` keys.
        ///
        /// When `true` (the default), Ed25519 keys advertise `"Ed25519"` as
        /// the JWS algorithm per [RFC 9864]. When `false`, the deprecated
        /// polymorphic `"EdDSA"` identifier is used instead.
        ///
        /// This only affects signing; it has no effect on other algorithms.
        ///
        /// [RFC 9864]: https://www.rfc-editor.org/rfc/rfc9864
        #[builder(default = true)]
        use_fully_specified_jws_algorithm: bool,
        /// The policy for deriving a `kid` from the key version ID. Defaults to
        /// [`VersionKid::none()`] (no `kid`).
        #[builder(default = VersionKid::none())]
        kid: VersionKid,
        /// Maximum number of enabled versions to load.
        ///
        /// When set, at most this many versions are fetched, in newest-first
        /// order. The API `page_size` is set to this value, so listing requires
        /// only one request when the number of enabled versions is within the
        /// limit. Retrieving each public key still requires a separate request.
        ///
        /// When unset, all enabled versions are fetched (may require multiple
        /// paged requests).
        max_versions: Option<usize>,
    ) -> Result<Self, SetupError> {
        // Resolve the primary version and list all enabled versions concurrently.
        let (primary_version_id, all_versions) = futures_util::try_join!(
            async {
                super::super::version::resolve_version(&key_name, &strategy, &kms_client)
                    .await
                    .context(VersionResolutionSnafu)
            },
            async {
                super::super::version::list_enabled_kms_versions(
                    &kms_client,
                    &key_name,
                    max_versions,
                    Some("name desc"),
                )
                .await
                .context(ListCryptoKeyVersionsSnafu)
            },
        )?;

        ensure!(!all_versions.is_empty(), NoEnabledCryptoKeyVersionsSnafu);

        let primary_resource_name = format!("{key_name}/cryptoKeyVersions/{primary_version_id}");
        let kms_ref = &kms_client;
        let kid_ref = &kid;

        // Fetch public keys for all enabled signing-capable versions concurrently.
        let futures: Vec<_> = all_versions
            .iter()
            .filter_map(|version| {
                let alg = get_jws_algorithm(&version.algorithm)?;
                let version_id =
                    super::super::version::version_id_from_resource_name(&version.name);
                let kid = kid_ref.derive(version_id);
                let name = &version.name;

                Some(async move {
                    let pk_response = kms_ref
                        .get_public_key()
                        .set_name(name)
                        .send()
                        .await
                        .context(GetPublicKeySnafu)?;

                    let jws_algorithm = if !use_fully_specified_jws_algorithm && alg == "Ed25519" {
                        "EdDSA"
                    } else {
                        alg
                    };

                    let public_key_jwk = parse_public_key_pem(
                        &pk_response.pem,
                        jws_algorithm,
                        kid.as_deref(),
                        jwk::KeyUse::Sign,
                    )
                    .context(PublicKeyParseSnafu)?;

                    let thumbprint = public_key_jwk.thumbprint();

                    Ok::<_, SetupError>(KeyVersion {
                        kms_client: kms_ref.clone(),
                        resource_name: name.clone(),
                        jws_algorithm: jws_algorithm.to_string(),
                        key_id: kid,
                        public_key_jwk,
                        thumbprint,
                    })
                })
            })
            .collect();

        let all_key_versions = futures_util::future::try_join_all(futures).await?;

        // Separate primary from additional versions.
        let mut primary = None;
        let mut additional = Vec::with_capacity(all_key_versions.len().saturating_sub(1));
        for kv in all_key_versions {
            if kv.resource_name == primary_resource_name {
                primary = Some(kv);
            } else {
                additional.push(kv);
            }
        }

        let primary = primary.context(PrimaryVersionNotFoundSnafu)?;

        Ok(Self {
            primary,
            additional,
        })
    }
}

impl JwsSignerSelector for SigningKey {
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        let signer: Arc<dyn JwsSigner> = Arc::new(self.primary.clone());
        Box::pin(async move { signer })
    }
}

impl AsymmetricJwsSignerSelector for SigningKey {
    fn select_asymmetric_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AsymmetricJwsSigner>> {
        let signer: Arc<dyn AsymmetricJwsSigner> = Arc::new(self.primary.clone());
        Box::pin(async move { signer })
    }

    fn select_signer_by_thumbprint<'a>(
        &'a self,
        thumbprint: &'a str,
    ) -> MaybeSendBoxFuture<'a, Option<Arc<dyn AsymmetricJwsSigner>>> {
        let signer: Option<Arc<dyn AsymmetricJwsSigner>> = if self.primary.thumbprint == thumbprint
        {
            Some(Arc::new(self.primary.clone()))
        } else {
            self.additional
                .iter()
                .find(|kv| kv.thumbprint == thumbprint)
                .map(|kv| Arc::new(kv.clone()) as Arc<dyn AsymmetricJwsSigner>)
        };
        Box::pin(async move { signer })
    }
}

// ─── Shared construction ─────────────────────────────────────────────────────

async fn build_key_version(
    resource_name: String,
    kms_client: KeyManagementService,
    use_fully_specified_jws_algorithm: bool,
    kid: VersionKid,
) -> Result<KeyVersion, SetupError> {
    // Fetch the public key — this also gives us the algorithm.
    let public_key_response = kms_client
        .get_public_key()
        .set_name(&resource_name)
        .send()
        .await
        .context(GetPublicKeySnafu)?;

    // Use the canonical name from the response to resolve aliases.
    // If the input was an alias (for example, ".../cryptoKeyVersions/primary"),
    // the response name will contain the resolved version (for example,
    // ".../cryptoKeyVersions/3").
    let resolved_name = if public_key_response.name.is_empty() {
        resource_name
    } else {
        public_key_response.name.clone()
    };
    let version_id = super::super::version::version_id_from_resource_name(&resolved_name);
    let key_id = kid.derive(version_id);

    let jws_algorithm = get_jws_algorithm(&public_key_response.algorithm).with_context(|| {
        UnsupportedAlgorithmSnafu {
            algorithm: public_key_response.algorithm,
        }
    })?;

    // For Ed25519, allow the caller to choose between the fully-specified
    // "Ed25519" (RFC 9864) and the deprecated polymorphic "EdDSA" identifier.
    let jws_algorithm = if !use_fully_specified_jws_algorithm && jws_algorithm == "Ed25519" {
        "EdDSA"
    } else {
        jws_algorithm
    };

    let public_key_jwk = parse_public_key_pem(
        &public_key_response.pem,
        jws_algorithm,
        key_id.as_deref(),
        jwk::KeyUse::Sign,
    )
    .context(PublicKeyParseSnafu)?;

    let thumbprint = public_key_jwk.thumbprint();

    Ok(KeyVersion {
        kms_client,
        resource_name: resolved_name,
        jws_algorithm: jws_algorithm.to_string(),
        key_id,
        public_key_jwk,
        thumbprint,
    })
}

// ─── Algorithm mapping ───────────────────────────────────────────────────────

pub(super) fn get_jws_algorithm(algorithm: &CryptoKeyVersionAlgorithm) -> Option<&'static str> {
    use CryptoKeyVersionAlgorithm::{
        EcSignEd25519, EcSignP256Sha256, EcSignP384Sha384, RsaSignPkcs12048Sha256,
        RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256, RsaSignPkcs14096Sha512,
        RsaSignPss2048Sha256, RsaSignPss3072Sha256, RsaSignPss4096Sha256, RsaSignPss4096Sha512,
    };

    match algorithm {
        RsaSignPss2048Sha256 | RsaSignPss3072Sha256 | RsaSignPss4096Sha256 => Some("PS256"),
        RsaSignPss4096Sha512 => Some("PS512"),
        RsaSignPkcs12048Sha256 | RsaSignPkcs13072Sha256 | RsaSignPkcs14096Sha256 => Some("RS256"),
        RsaSignPkcs14096Sha512 => Some("RS512"),
        EcSignP256Sha256 => Some("ES256"),
        EcSignP384Sha384 => Some("ES384"),
        EcSignEd25519 => Some("Ed25519"),
        _ => None,
    }
}

pub(super) fn get_jwe_algorithm(algorithm: &CryptoKeyVersionAlgorithm) -> Option<&'static str> {
    use CryptoKeyVersionAlgorithm::{
        RsaDecryptOaep2048Sha1, RsaDecryptOaep2048Sha256, RsaDecryptOaep3072Sha1,
        RsaDecryptOaep3072Sha256, RsaDecryptOaep4096Sha1, RsaDecryptOaep4096Sha256,
        RsaDecryptOaep4096Sha512,
    };

    match algorithm {
        RsaDecryptOaep2048Sha1 | RsaDecryptOaep3072Sha1 | RsaDecryptOaep4096Sha1 => {
            Some("RSA-OAEP")
        }
        RsaDecryptOaep2048Sha256 | RsaDecryptOaep3072Sha256 | RsaDecryptOaep4096Sha256 => {
            Some("RSA-OAEP-256")
        }
        RsaDecryptOaep4096Sha512 => Some("RSA-OAEP-512"),
        _ => None,
    }
}

// ─── Public key parsing ──────────────────────────────────────────────────────

/// Parses a public key PEM (from KMS) into a [`PublicJwk`].
pub(super) fn parse_public_key_pem(
    pem: &str,
    algorithm: &str,
    kid: Option<&str>,
    key_use: jwk::KeyUse,
) -> Result<PublicJwk, PublicKeyParseError> {
    match algorithm {
        "ES256" => parse_ec_p256_public_key(pem, kid, key_use),
        "ES384" => parse_ec_p384_public_key(pem, kid, key_use),
        "RS256" | "RS512" | "PS256" | "PS512" | "RSA-OAEP" | "RSA-OAEP-256" | "RSA-OAEP-512" => {
            parse_rsa_public_key(pem, algorithm, kid, key_use)
        }
        "Ed25519" | "EdDSA" => parse_ed25519_public_key(pem, algorithm, kid, key_use),
        _ => UnsupportedParseAlgorithmSnafu {
            algorithm: algorithm.to_owned(),
        }
        .fail(),
    }
}

fn parse_ec_p256_public_key(
    pem: &str,
    kid: Option<&str>,
    key_use: jwk::KeyUse,
) -> Result<PublicJwk, PublicKeyParseError> {
    let pk =
        p256::PublicKey::from_public_key_pem(pem).context(EcDecodeSnafu { algorithm: "ES256" })?;
    let point = pk.to_sec1_point(false);
    let x = point
        .x()
        .context(MissingCoordinateSnafu { algorithm: "ES256" })?;
    let y = point
        .y()
        .context(MissingCoordinateSnafu { algorithm: "ES256" })?;
    Ok(PublicJwk::builder()
        .algorithm("ES256")
        .maybe_kid(kid)
        .key_use(key_use)
        .key(
            jwk::EcPublicKey::builder()
                .crv("P-256")
                .x(x.to_vec())
                .y(y.to_vec()),
        )
        .build())
}

fn parse_ec_p384_public_key(
    pem: &str,
    kid: Option<&str>,
    key_use: jwk::KeyUse,
) -> Result<PublicJwk, PublicKeyParseError> {
    let pk =
        p384::PublicKey::from_public_key_pem(pem).context(EcDecodeSnafu { algorithm: "ES384" })?;
    let point = pk.to_sec1_point(false);
    let x = point
        .x()
        .context(MissingCoordinateSnafu { algorithm: "ES384" })?;
    let y = point
        .y()
        .context(MissingCoordinateSnafu { algorithm: "ES384" })?;
    Ok(PublicJwk::builder()
        .algorithm("ES384")
        .maybe_kid(kid)
        .key_use(key_use)
        .key(
            jwk::EcPublicKey::builder()
                .crv("P-384")
                .x(x.to_vec())
                .y(y.to_vec()),
        )
        .build())
}

fn parse_rsa_public_key(
    pem: &str,
    algorithm: &str,
    kid: Option<&str>,
    key_use: jwk::KeyUse,
) -> Result<PublicJwk, PublicKeyParseError> {
    let der_bytes = decode_pem(pem).context(PemDecodeSnafu)?;
    let spki = spki::SubjectPublicKeyInfoRef::from_der(&der_bytes).context(SpkiParseSnafu)?;
    let pk_bytes = spki.subject_public_key.raw_bytes();

    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let rsa_pk = RsaPublicKeyAsn1::from_der(pk_bytes).context(RsaParseSnafu)?;

    Ok(PublicJwk::builder()
        .algorithm(algorithm)
        .maybe_kid(kid)
        .key_use(key_use)
        .key(
            jwk::RsaPublicKey::builder()
                .n(rsa_pk.modulus.as_bytes().to_vec())
                .e(rsa_pk.public_exponent.as_bytes().to_vec()),
        )
        .build())
}

fn parse_ed25519_public_key(
    pem: &str,
    algorithm: &str,
    kid: Option<&str>,
    key_use: jwk::KeyUse,
) -> Result<PublicJwk, PublicKeyParseError> {
    let der_bytes = decode_pem(pem).context(PemDecodeSnafu)?;
    let spki = spki::SubjectPublicKeyInfoRef::from_der(&der_bytes).context(SpkiParseSnafu)?;
    let pk_bytes = spki.subject_public_key.raw_bytes();

    ensure!(
        pk_bytes.len() == 32,
        Ed25519LengthSnafu {
            length: pk_bytes.len()
        }
    );

    Ok(PublicJwk::builder()
        .algorithm(algorithm)
        .maybe_kid(kid)
        .key_use(key_use)
        .key(
            jwk::OkpPublicKey::builder()
                .crv("Ed25519")
                .x(pk_bytes.to_vec()),
        )
        .build())
}

/// Decode a PEM string to DER bytes.
fn decode_pem(pem: &str) -> Result<Vec<u8>, pem_rfc7468::Error> {
    pem_rfc7468::decode_vec(pem.as_bytes()).map(|(_label, der)| der)
}

/// ASN.1 structure for an RSA public key.
#[derive(der::Sequence)]
struct RsaPublicKeyAsn1<'a> {
    modulus: der::asn1::UintRef<'a>,
    public_exponent: der::asn1::UintRef<'a>,
}

// ─── ECDSA signature conversion ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EcDsaVariant {
    P256,
    P384,
}

/// Converts a DER-encoded ECDSA signature to fixed-size (r || s) format for JWT.
///
/// GCP KMS returns ECDSA signatures in DER format (ASN.1 SEQUENCE), but JWT/JWS
/// requires IEEE P1363 format (raw r||s concatenation).
fn convert_ecdsa_der_to_fixed(
    der_sig: &[u8],
    variant: EcDsaVariant,
) -> Result<Vec<u8>, signature::Error> {
    match variant {
        EcDsaVariant::P256 => {
            let sig = p256::ecdsa::Signature::from_der(der_sig)?;
            Ok(sig.to_bytes().to_vec())
        }
        EcDsaVariant::P384 => {
            let sig = p384::ecdsa::Signature::from_der(der_sig)?;
            Ok(sig.to_bytes().to_vec())
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const RSA_2048_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n\
        4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n\
        +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\n\
        kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\n\
        0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\n\
        cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\n\
        mwIDAQAB\n\
        -----END PUBLIC KEY-----";

    const P256_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh07Vhy18exUbbDOWC8KFtcUnw1nL\n\
        hU0zM/L+vXZ2QJRykZKgVHVizTVnAw2jEszcMCY6CiAR2TU2SNhNhASV/g==\n\
        -----END PUBLIC KEY-----";

    const P384_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE0W/oUiIVHc69FmdLEAnBm6J5xXDBjhBh\n\
        3YOaHjc6bQ9Rqqiinpvq5s4K3ob4WtZrrHQQNldYsxRCeoW5imtuhz55J8nrXyh1\n\
        hYo8wqhEAWj4k4lWZQ4F+eFa4dzRkgUP\n\
        -----END PUBLIC KEY-----";

    const ED25519_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
        -----END PUBLIC KEY-----";

    use std::future::Future;

    use google_cloud_gax::{Result as GaxResult, options::RequestOptions, response::Response};
    use google_cloud_kms_v1::{
        model::{AsymmetricSignRequest, AsymmetricSignResponse},
        stub::KeyManagementService as KmsStub,
    };
    use rstest::rstest;

    const RESOURCE: &str = "projects/p/.../cryptoKeyVersions/1";

    #[derive(Debug, Clone, Default)]
    struct MockKms {
        response_name: String,
        signature: Vec<u8>,
    }

    impl KmsStub for MockKms {
        fn asymmetric_sign(
            &self,
            _req: AsymmetricSignRequest,
            _options: RequestOptions,
        ) -> impl Future<Output = GaxResult<Response<AsymmetricSignResponse>>> + Send {
            let resp = AsymmetricSignResponse::default()
                .set_name(self.response_name.clone())
                .set_signature(self.signature.clone());
            async move { Ok(Response::from(resp)) }
        }
    }

    /// Builds a signing `KeyVersion` backed by the stub. The public key is real
    /// (parsed from a constant) so the struct is well-formed; signing behaviour
    /// is driven entirely by the stub and `jws_algorithm`.
    fn signing_key_version(mock: MockKms, jws_algorithm: &str) -> KeyVersion {
        let public_key_jwk =
            parse_public_key_pem(P256_PUBLIC_KEY_PEM, "ES256", None, jwk::KeyUse::Sign).unwrap();
        let thumbprint = public_key_jwk.thumbprint();
        KeyVersion {
            kms_client: KeyManagementService::from_stub(mock),
            resource_name: RESOURCE.to_owned(),
            jws_algorithm: jws_algorithm.to_owned(),
            key_id: None,
            public_key_jwk,
            thumbprint,
        }
    }

    #[rstest]
    #[case(P256_PUBLIC_KEY_PEM, "ES256", Some("test-kid"), jwk::KeyUse::Sign)]
    #[case(P384_PUBLIC_KEY_PEM, "ES384", None, jwk::KeyUse::Sign)]
    #[case(RSA_2048_PUBLIC_KEY_PEM, "RS256", Some("rsa-kid"), jwk::KeyUse::Sign)]
    #[case(RSA_2048_PUBLIC_KEY_PEM, "PS256", None, jwk::KeyUse::Sign)]
    #[case(ED25519_PUBLIC_KEY_PEM, "Ed25519", Some("ed-kid"), jwk::KeyUse::Sign)]
    #[case(ED25519_PUBLIC_KEY_PEM, "EdDSA", Some("ed-kid"), jwk::KeyUse::Sign)]
    #[case(
        RSA_2048_PUBLIC_KEY_PEM,
        "RSA-OAEP-256",
        Some("enc-kid"),
        jwk::KeyUse::Encrypt
    )]
    fn parse_public_key_pem_succeeds(
        #[case] pem: &str,
        #[case] algorithm: &str,
        #[case] kid: Option<&str>,
        #[case] key_use: jwk::KeyUse,
    ) {
        let jwk = parse_public_key_pem(pem, algorithm, kid, key_use).unwrap();
        assert_eq!(jwk.algorithm.as_deref(), Some(algorithm));
        assert_eq!(jwk.kid.as_deref(), kid);
        assert_eq!(jwk.key_use, Some(key_use));
    }

    #[rstest]
    #[case(P256_PUBLIC_KEY_PEM, "RS256")] // RSA algorithm against an EC PEM
    #[case("not a PEM", "ES256")]
    fn parse_public_key_pem_rejects_bad_input(#[case] pem: &str, #[case] algorithm: &str) {
        assert!(parse_public_key_pem(pem, algorithm, None, jwk::KeyUse::Sign).is_err());
    }

    #[test]
    fn parse_unsupported_algorithm_fails() {
        let result = parse_public_key_pem(P256_PUBLIC_KEY_PEM, "HS256", None, jwk::KeyUse::Sign);
        assert!(matches!(
            result.unwrap_err(),
            PublicKeyParseError::UnsupportedParseAlgorithm { .. }
        ));
    }

    #[test]
    fn parse_rsa_and_ec_produce_different_thumbprints() {
        let rsa_jwk =
            parse_public_key_pem(RSA_2048_PUBLIC_KEY_PEM, "RS256", None, jwk::KeyUse::Sign)
                .unwrap();
        let ec_jwk =
            parse_public_key_pem(P256_PUBLIC_KEY_PEM, "ES256", None, jwk::KeyUse::Sign).unwrap();
        assert_ne!(rsa_jwk.thumbprint(), ec_jwk.thumbprint());
    }

    #[rstest]
    #[case(CryptoKeyVersionAlgorithm::RsaSignPss2048Sha256, Some("PS256"))]
    #[case(CryptoKeyVersionAlgorithm::RsaSignPss4096Sha512, Some("PS512"))]
    #[case(CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256, Some("RS256"))]
    #[case(CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha512, Some("RS512"))]
    #[case(CryptoKeyVersionAlgorithm::EcSignP256Sha256, Some("ES256"))]
    #[case(CryptoKeyVersionAlgorithm::EcSignP384Sha384, Some("ES384"))]
    #[case(CryptoKeyVersionAlgorithm::EcSignEd25519, Some("Ed25519"))]
    #[case(CryptoKeyVersionAlgorithm::RsaDecryptOaep2048Sha256, None)] // not a signing alg
    fn get_jws_algorithm_maps_signing_algorithms(
        #[case] algorithm: CryptoKeyVersionAlgorithm,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(get_jws_algorithm(&algorithm), expected);
    }

    #[rstest]
    #[case(CryptoKeyVersionAlgorithm::RsaDecryptOaep2048Sha1, Some("RSA-OAEP"))]
    #[case(CryptoKeyVersionAlgorithm::RsaDecryptOaep4096Sha1, Some("RSA-OAEP"))]
    #[case(
        CryptoKeyVersionAlgorithm::RsaDecryptOaep2048Sha256,
        Some("RSA-OAEP-256")
    )]
    #[case(
        CryptoKeyVersionAlgorithm::RsaDecryptOaep4096Sha256,
        Some("RSA-OAEP-256")
    )]
    #[case(
        CryptoKeyVersionAlgorithm::RsaDecryptOaep4096Sha512,
        Some("RSA-OAEP-512")
    )]
    #[case(CryptoKeyVersionAlgorithm::EcSignP256Sha256, None)] // signing key, not JWE
    #[case(CryptoKeyVersionAlgorithm::RsaSignPss2048Sha256, None)]
    fn get_jwe_algorithm_maps_encryption_algorithms(
        #[case] algorithm: CryptoKeyVersionAlgorithm,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(get_jwe_algorithm(&algorithm), expected);
    }

    #[test]
    fn convert_ecdsa_der_to_fixed_p256_roundtrips() {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};

        let sk = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let sig: Signature = sk.sign(b"message");
        let fixed =
            convert_ecdsa_der_to_fixed(sig.to_der().as_bytes(), EcDsaVariant::P256).unwrap();

        assert_eq!(fixed.len(), 64); // r || s, 32 bytes each
        assert_eq!(fixed, sig.to_bytes().to_vec());
    }

    #[test]
    fn convert_ecdsa_der_to_fixed_p384_roundtrips() {
        use p384::ecdsa::{Signature, SigningKey, signature::Signer};

        let sk = SigningKey::from_slice(&[1u8; 48]).unwrap();
        let sig: Signature = sk.sign(b"message");
        let fixed =
            convert_ecdsa_der_to_fixed(sig.to_der().as_bytes(), EcDsaVariant::P384).unwrap();

        assert_eq!(fixed.len(), 96); // r || s, 48 bytes each
        assert_eq!(fixed, sig.to_bytes().to_vec());
    }

    #[test]
    fn signing_error_advises_against_retry() {
        assert!(!SigningError::MismatchedKeyInfo.is_retryable());
        assert_eq!(
            huskarl_core::Error::from(SigningError::MismatchedKeyInfo).retry_advice(),
            RetryAdvice::No
        );
    }

    #[test]
    fn setup_error_classifies_by_retryability() {
        // A non-retryable setup failure advises against a retry so a refresh
        // factory (such as `ScheduledRefreshSigner`) surfaces a permanent build
        // error instead of spinning on it.
        let permanent = SetupError::UnsupportedAlgorithm {
            algorithm: CryptoKeyVersionAlgorithm::default(),
        };
        assert!(!permanent.is_retryable());
        assert_eq!(
            huskarl_core::Error::from(permanent).retry_advice(),
            RetryAdvice::No
        );
    }

    #[tokio::test]
    async fn sign_converts_ecdsa_der_to_fixed_p1363() {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};

        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let sig: Signature = sk.sign(b"jwt-signing-input");
        // KMS hands back a DER-encoded ECDSA signature.
        let mock = MockKms {
            response_name: RESOURCE.to_owned(),
            signature: sig.to_der().as_bytes().to_vec(),
        };
        let kv = signing_key_version(mock, "ES256");

        // The signer must convert it to the fixed-width r || s JWS form.
        let out = kv.sign(b"jwt-signing-input").await.unwrap();
        assert_eq!(out, sig.to_bytes().to_vec());
    }

    #[tokio::test]
    async fn sign_passes_through_non_ecdsa_signatures() {
        let mock = MockKms {
            response_name: RESOURCE.to_owned(),
            signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let kv = signing_key_version(mock, "RS256");

        // RSA signatures are already in the right form — returned verbatim.
        assert_eq!(
            kv.sign(b"data").await.unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[tokio::test]
    async fn sign_rejects_mismatched_key_name() {
        let mock = MockKms {
            response_name: "projects/p/.../cryptoKeyVersions/2".to_owned(),
            signature: vec![1, 2, 3],
        };
        let kv = signing_key_version(mock, "RS256");

        let err = kv.sign(b"data").await.unwrap_err();
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }
}
