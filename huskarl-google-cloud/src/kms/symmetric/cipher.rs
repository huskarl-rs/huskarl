//! Encryption and decryption with symmetric AEAD Cloud KMS keys.

use std::borrow::Cow;
use std::sync::Arc;

use bon::bon;
use google_cloud_kms_v1::{
    client::KeyManagementService, model::crypto_key_version::CryptoKeyVersionAlgorithm,
};
use huskarl_core::RetryAdvice;
use huskarl_core::crypto::KeyMatchStrength;
use huskarl_core::crypto::cipher::{
    AeadDecryptor, AeadEncryptor, AeadEncryptorSelector, AeadOutput, CipherMatch, DecryptError,
    MultiKeyDecryptor,
};
use huskarl_core::platform::MaybeSendBoxFuture;
use snafu::prelude::*;

use super::super::version::{self, VersionStrategy};
use super::setup;
use super::{
    GetCryptoKeyVersionSnafu, ListCryptoKeyVersionsSnafu, NoEnabledCryptoKeyVersionsSnafu,
    ResolveVersionSnafu, UnsupportedAlgorithmSnafu,
};
pub use super::{KeyError, SetupError};

use crate::kid::VersionKid;

/// An error returned while encrypting with a symmetric KMS key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum EncryptionError {
    /// Failed to encrypt data with the key.
    RawEncrypt {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// The response named a different key version from the request.
    ///
    /// The ciphertext is discarded because it cannot be attributed to the
    /// requested version.
    MismatchedKeyInfo,
}

/// An error returned while decrypting with a symmetric KMS key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum DecryptionError {
    /// Failed to decrypt data with the key.
    RawDecrypt {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
}

impl EncryptionError {
    /// Returns advice about retrying the failed operation.
    ///
    /// If the service supplied a minimum delay in the RPC's `RetryInfo` detail,
    /// the returned [`RetryAdvice`] preserves it.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            EncryptionError::RawEncrypt { source } => crate::retry::advice(source),
            EncryptionError::MismatchedKeyInfo => RetryAdvice::No,
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

impl From<EncryptionError> for huskarl_core::Error {
    #[track_caller]
    fn from(err: EncryptionError) -> Self {
        huskarl_core::Error::new(err.retry_advice(), err)
    }
}

impl DecryptionError {
    /// Returns advice about retrying the failed operation.
    ///
    /// If the service supplied a minimum delay in the RPC's `RetryInfo` detail,
    /// the returned [`RetryAdvice`] preserves it.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            DecryptionError::RawDecrypt { source } => crate::retry::advice(source),
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

impl From<DecryptionError> for huskarl_core::Error {
    #[track_caller]
    fn from(err: DecryptionError) -> Self {
        huskarl_core::Error::new(err.retry_advice(), err)
    }
}

// ─── KeyVersion ──────────────────────────────────────────────────────────────

/// An AEAD key bound to a specific Cloud KMS key version.
///
/// This is the lowest-level cipher primitive: it holds a reference to a
/// specific `CryptoKeyVersion` resource and delegates all raw encrypt/decrypt
/// operations to Cloud KMS.
///
/// This type implements [`AeadEncryptor`], [`AeadDecryptor`], and
/// [`AeadEncryptorSelector`] (selecting itself).
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::symmetric::cipher::KeyVersion;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = KeyVersion::builder()
///   .resource_name("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
///   .kms_client(kms_client)
///   .build()
///   .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct KeyVersion {
    kms_client: KeyManagementService,
    resource_name: String,
    enc_algorithm: String,
    key_id: Option<String>,
}

#[bon]
impl KeyVersion {
    /// Creates a `KeyVersion` from a Cloud KMS AEAD key version resource name.
    ///
    /// Fetches the key version metadata from KMS to determine the algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if the key version metadata could not be retrieved
    /// or the algorithm is not a supported AEAD algorithm.
    #[builder(finish_fn = build)]
    pub async fn builder(
        /// The full resource name of the crypto key version.
        #[builder(into)]
        resource_name: String,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// The policy for deriving a `kid` from the key version ID. Defaults to
        /// [`VersionKid::none()`] (no `kid`).
        #[builder(default = VersionKid::none())]
        kid: VersionKid,
    ) -> Result<Self, SetupError> {
        build_key_version(resource_name, kms_client, kid).await
    }
}

impl AeadEncryptorSelector for KeyVersion {
    fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
        let encryptor: Arc<dyn AeadEncryptor> = Arc::new(self.clone());
        Box::pin(async move { encryptor })
    }
}

impl AeadEncryptor for KeyVersion {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.enc_algorithm)
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.key_id.as_deref().map(Cow::Borrowed)
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, huskarl_core::Error>> {
        Box::pin(async move {
            let response = self
                .kms_client
                .raw_encrypt()
                .set_name(&self.resource_name)
                .set_plaintext(plaintext.to_vec())
                .set_additional_authenticated_data(aad.to_vec())
                // Omit `initialization_vector`; KMS generates and returns it.
                .send()
                .await
                .context(RawEncryptSnafu)?;

            if response.name != self.resource_name {
                return Err(EncryptionError::MismatchedKeyInfo.into());
            }

            let tag_length = usize::try_from(response.tag_length).unwrap_or(0);
            let ct_with_tag = response.ciphertext;

            // The tag is appended to the end of the ciphertext by KMS.
            let split_at = ct_with_tag.len().saturating_sub(tag_length);
            let ciphertext = ct_with_tag[..split_at].to_vec();
            let tag = ct_with_tag[split_at..].to_vec();
            let nonce = response.initialization_vector.to_vec();

            Ok(AeadOutput {
                nonce,
                ciphertext,
                tag,
            })
        })
    }
}

impl AeadDecryptor for KeyVersion {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        m.strength_for(&self.enc_algorithm, self.key_id.as_deref())
    }

    fn decrypt<'a>(
        &'a self,
        _cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async move {
            // KMS RawDecrypt expects the tag appended to the ciphertext.
            let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + tag.len());
            ct_with_tag.extend_from_slice(ciphertext);
            ct_with_tag.extend_from_slice(tag);

            let response = self
                .kms_client
                .raw_decrypt()
                .set_name(&self.resource_name)
                .set_ciphertext(ct_with_tag)
                .set_initialization_vector(nonce.to_vec())
                .set_additional_authenticated_data(aad.to_vec())
                .set_tag_length(i32::try_from(tag.len()).unwrap_or(16))
                .send()
                .await
                .context(RawDecryptSnafu)
                .map_err(huskarl_core::Error::from)?;

            Ok(response.plaintext.to_vec())
        })
    }
}

// ─── EncryptionKey ────────────────────────────────────────────────────────────

/// A Cloud KMS AEAD encryption key bound to a specific key version.
///
/// Resolves a key version using the configured [`VersionStrategy`],
/// then delegates encryption to the resolved [`KeyVersion`].
///
/// This type implements [`AeadEncryptor`] and [`AeadEncryptorSelector`].
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::{VersionStrategy, symmetric::cipher::EncryptionKey};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = EncryptionKey::builder()
///   .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///   .kms_client(kms_client)
///   .strategy(VersionStrategy::ByLabel("active_version".into()))
///   .build()
///   .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    key_version: KeyVersion,
}

#[bon]
impl EncryptionKey {
    /// Creates an `EncryptionKey` from a Cloud KMS AEAD key resource name.
    ///
    /// Resolves the key version using the configured strategy and fetches its
    /// metadata from KMS.
    ///
    /// # Errors
    ///
    /// Returns an error if version resolution fails, metadata cannot be
    /// retrieved, or the algorithm is not a supported AEAD algorithm.
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
        /// The policy for deriving a `kid` from the key version ID. Defaults to
        /// [`VersionKid::none()`] (no `kid`).
        #[builder(default = VersionKid::none())]
        kid: VersionKid,
    ) -> Result<Self, KeyError> {
        let key_version =
            resolve_encryption_key_version(&key_name, &kms_client, &strategy, &kid).await?;
        Ok(Self { key_version })
    }
}

impl AeadEncryptorSelector for EncryptionKey {
    fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
        let encryptor: Arc<dyn AeadEncryptor> = Arc::new(self.key_version.clone());
        Box::pin(async move { encryptor })
    }
}

impl AeadEncryptor for EncryptionKey {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.key_version.enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.key_version.key_id()
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, huskarl_core::Error>> {
        self.key_version.encrypt(plaintext, aad)
    }
}

// ─── DecryptionKey ────────────────────────────────────────────────────────────

/// A Cloud KMS AEAD decryption key spanning all enabled key versions.
///
/// This type implements [`AeadDecryptor`], decrypting against all enabled
/// versions to support key rotation.
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::symmetric::cipher::DecryptionKey;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = DecryptionKey::builder()
///   .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///   .kms_client(kms_client)
///   .build()
///   .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct DecryptionKey {
    decryptor: Arc<MultiKeyDecryptor>,
}

impl std::fmt::Debug for DecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptionKey").finish_non_exhaustive()
    }
}

#[bon]
impl DecryptionKey {
    /// Creates a `DecryptionKey` from a Cloud KMS AEAD key resource name.
    ///
    /// Lists all enabled versions and builds a [`MultiKeyDecryptor`] from them,
    /// enabling rotation-safe decryption.
    ///
    /// # Errors
    ///
    /// Returns an error if listing fails or no enabled versions are found.
    #[builder(finish_fn = build)]
    pub async fn builder(
        /// The full resource name of the crypto key.
        #[builder(into)]
        key_name: String,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// The policy for deriving a `kid` from the key version ID. Defaults to
        /// [`VersionKid::none()`] (no `kid`).
        #[builder(default = VersionKid::none())]
        kid: VersionKid,
        /// Maximum number of enabled versions to fetch.
        ///
        /// When set, at most this many versions are fetched, in newest-first
        /// order. The API `page_size` is set to this value, so listing requires
        /// only one request when the number of enabled versions is within the
        /// limit.
        ///
        /// When unset, all enabled versions are fetched (may require multiple
        /// paged requests).
        max_versions: Option<usize>,
    ) -> Result<Self, KeyError> {
        let versions =
            resolve_decryption_key_versions(&key_name, &kms_client, &kid, max_versions).await?;
        let decryptor = Arc::new(MultiKeyDecryptor::new(
            versions
                .into_iter()
                .map(|kv| Arc::new(kv) as Arc<dyn AeadDecryptor>)
                .collect(),
        ));
        Ok(Self { decryptor })
    }
}

impl AeadDecryptor for DecryptionKey {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.decryptor.cipher_match(m)
    }

    fn decrypt<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        self.decryptor
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
    }
}

// ─── CipherKey ───────────────────────────────────────────────────────────────

/// A Cloud KMS AEAD key that can both encrypt and decrypt.
///
/// Encrypts with a single version resolved by the configured
/// [`VersionStrategy`], and decrypts with all enabled versions to support
/// key rotation.
///
/// This type implements [`AeadEncryptor`], [`AeadEncryptorSelector`], and
/// [`AeadDecryptor`]. Both sides are constructed concurrently.
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::{VersionStrategy, symmetric::cipher::CipherKey};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = CipherKey::builder()
///   .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///   .kms_client(kms_client)
///   .strategy(VersionStrategy::ByLabel("active_version".into()))
///   .build()
///   .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct CipherKey {
    encryption: EncryptionKey,
    decryption: DecryptionKey,
}

impl std::fmt::Debug for CipherKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherKey")
            .field("encryption", &self.encryption)
            .finish_non_exhaustive()
    }
}

#[bon]
impl CipherKey {
    /// Creates a `CipherKey` from a Cloud KMS AEAD key resource name.
    ///
    /// Resolves the encryption version and lists all decryption versions
    /// concurrently.
    ///
    /// # Errors
    ///
    /// Returns an error if version resolution fails, metadata cannot be
    /// retrieved, listing fails, no enabled versions are found, or the
    /// algorithm is not a supported AEAD algorithm.
    #[builder(finish_fn = build)]
    pub async fn builder(
        /// The full resource name of the crypto key.
        #[builder(into)]
        key_name: String,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// The version selection strategy for encryption. Defaults to [`VersionStrategy::Latest`].
        #[builder(default)]
        strategy: VersionStrategy,
        /// The policy for deriving a `kid` from the key version ID. Defaults to
        /// [`VersionKid::none()`] (no `kid`).
        #[builder(default = VersionKid::none())]
        kid: VersionKid,
        /// Maximum number of enabled versions to fetch for decryption.
        ///
        /// When set, at most this many versions are fetched, in newest-first
        /// order. The API `page_size` is set to this value, so listing requires
        /// only one request when the number of enabled versions is within the
        /// limit.
        ///
        /// When unset, all enabled versions are fetched (may require multiple
        /// paged requests).
        max_versions: Option<usize>,
    ) -> Result<Self, KeyError> {
        let (enc_kv, dec_kvs) = futures_util::try_join!(
            resolve_encryption_key_version(&key_name, &kms_client, &strategy, &kid),
            resolve_decryption_key_versions(&key_name, &kms_client, &kid, max_versions),
        )?;
        let encryption = EncryptionKey {
            key_version: enc_kv,
        };
        let decryption = DecryptionKey {
            decryptor: Arc::new(MultiKeyDecryptor::new(
                dec_kvs
                    .into_iter()
                    .map(|kv| Arc::new(kv) as Arc<dyn AeadDecryptor>)
                    .collect(),
            )),
        };
        Ok(Self {
            encryption,
            decryption,
        })
    }
}

impl AeadEncryptorSelector for CipherKey {
    fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
        let encryptor: Arc<dyn AeadEncryptor> = Arc::new(self.encryption.key_version.clone());
        Box::pin(async move { encryptor })
    }
}

impl AeadEncryptor for CipherKey {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.encryption.enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.encryption.key_id()
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, huskarl_core::Error>> {
        self.encryption.encrypt(plaintext, aad)
    }
}

impl AeadDecryptor for CipherKey {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.decryption.cipher_match(m)
    }

    fn decrypt<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        self.decryption
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
    }
}

// ─── Shared construction ─────────────────────────────────────────────────────

async fn resolve_encryption_key_version(
    key_name: &str,
    kms_client: &KeyManagementService,
    strategy: &VersionStrategy,
    kid: &VersionKid,
) -> Result<KeyVersion, KeyError> {
    let version_id = version::resolve_version(key_name, strategy, kms_client)
        .await
        .context(ResolveVersionSnafu)?;

    let resource_name = format!("{key_name}/cryptoKeyVersions/{version_id}");

    let kv_response = kms_client
        .get_crypto_key_version()
        .set_name(&resource_name)
        .send()
        .await
        .context(GetCryptoKeyVersionSnafu)?;

    // Use the canonical name from the response to resolve aliases.
    let resolved_name = if kv_response.name.is_empty() {
        resource_name
    } else {
        kv_response.name
    };
    let vid = version::version_id_from_resource_name(&resolved_name);
    let key_id = kid.derive(vid);

    let enc_algorithm = get_enc_algorithm(&kv_response.algorithm).ok_or_else(|| {
        UnsupportedAlgorithmSnafu {
            algorithm: kv_response.algorithm,
        }
        .build()
    })?;

    Ok(KeyVersion {
        kms_client: kms_client.clone(),
        resource_name: resolved_name,
        enc_algorithm: enc_algorithm.to_string(),
        key_id,
    })
}

async fn resolve_decryption_key_versions(
    key_name: &str,
    kms_client: &KeyManagementService,
    kid: &VersionKid,
    max_versions: Option<usize>,
) -> Result<Vec<KeyVersion>, KeyError> {
    let raw =
        version::list_enabled_kms_versions(kms_client, key_name, max_versions, Some("name desc"))
            .await
            .context(ListCryptoKeyVersionsSnafu)?;

    ensure!(!raw.is_empty(), NoEnabledCryptoKeyVersionsSnafu);

    Ok(raw
        .iter()
        .filter_map(|v| {
            let enc_algorithm = get_enc_algorithm(&v.algorithm)?;
            let vid = version::version_id_from_resource_name(&v.name);
            let key_id = kid.derive(vid);
            Some(KeyVersion {
                kms_client: kms_client.clone(),
                resource_name: v.name.clone(),
                enc_algorithm: enc_algorithm.to_string(),
                key_id,
            })
        })
        .collect())
}

async fn build_key_version(
    resource_name: String,
    kms_client: KeyManagementService,
    kid: VersionKid,
) -> Result<KeyVersion, SetupError> {
    let kv_response = kms_client
        .get_crypto_key_version()
        .set_name(&resource_name)
        .send()
        .await
        .context(setup::GetCryptoKeyVersionSnafu)?;

    // Use the canonical name from the response to resolve aliases.
    let resolved_name = if kv_response.name.is_empty() {
        resource_name
    } else {
        kv_response.name
    };
    let version_id = version::version_id_from_resource_name(&resolved_name);
    let key_id = kid.derive(version_id);

    let enc_algorithm =
        get_enc_algorithm(&kv_response.algorithm).context(setup::UnsupportedAlgorithmSnafu {
            algorithm: kv_response.algorithm,
        })?;

    Ok(KeyVersion {
        kms_client,
        resource_name: resolved_name,
        enc_algorithm: enc_algorithm.to_string(),
        key_id,
    })
}

// ─── Algorithm mapping ───────────────────────────────────────────────────────

fn get_enc_algorithm(algorithm: &CryptoKeyVersionAlgorithm) -> Option<&'static str> {
    use CryptoKeyVersionAlgorithm::{Aes128Gcm, Aes256Gcm};

    match algorithm {
        Aes128Gcm => Some("A128GCM"),
        Aes256Gcm => Some("A256GCM"),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::future::Future;

    use google_cloud_gax::Result as GaxResult;
    use google_cloud_gax::options::RequestOptions;
    use google_cloud_gax::response::Response;
    use google_cloud_kms_v1::model::{
        RawDecryptRequest, RawDecryptResponse, RawEncryptRequest, RawEncryptResponse,
    };
    use google_cloud_kms_v1::stub::KeyManagementService as KmsStub;
    use rstest::rstest;

    use super::*;

    /// A canned KMS stub. `raw_encrypt` returns the configured bundle; `raw_decrypt`
    /// echoes the request ciphertext back as plaintext so a test can assert how the
    /// `[ciphertext || tag]` buffer was assembled.
    #[derive(Debug, Clone, Default)]
    struct MockKms {
        response_name: String,
        ciphertext: Vec<u8>,
        tag_length: i32,
        iv: Vec<u8>,
    }

    impl KmsStub for MockKms {
        fn raw_encrypt(
            &self,
            _req: RawEncryptRequest,
            _options: RequestOptions,
        ) -> impl Future<Output = GaxResult<Response<RawEncryptResponse>>> + Send {
            let resp = RawEncryptResponse::default()
                .set_name(self.response_name.clone())
                .set_ciphertext(self.ciphertext.clone())
                .set_tag_length(self.tag_length)
                .set_initialization_vector(self.iv.clone());
            async move { Ok(Response::from(resp)) }
        }

        fn raw_decrypt(
            &self,
            req: RawDecryptRequest,
            _options: RequestOptions,
        ) -> impl Future<Output = GaxResult<Response<RawDecryptResponse>>> + Send {
            // Echo the assembled ciphertext back so the test can inspect it.
            let resp = RawDecryptResponse::default().set_plaintext(req.ciphertext);
            async move { Ok(Response::from(resp)) }
        }
    }

    fn key_version(mock: MockKms, enc_algorithm: &str, key_id: Option<&str>) -> KeyVersion {
        KeyVersion {
            kms_client: KeyManagementService::from_stub(mock),
            resource_name: "projects/p/.../cryptoKeyVersions/1".to_owned(),
            enc_algorithm: enc_algorithm.to_owned(),
            key_id: key_id.map(str::to_owned),
        }
    }

    #[rstest]
    #[case(CryptoKeyVersionAlgorithm::Aes128Gcm, Some("A128GCM"))]
    #[case(CryptoKeyVersionAlgorithm::Aes256Gcm, Some("A256GCM"))]
    #[case(CryptoKeyVersionAlgorithm::HmacSha256, None)]
    fn get_enc_algorithm_maps_aead_algorithms(
        #[case] algorithm: CryptoKeyVersionAlgorithm,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(get_enc_algorithm(&algorithm), expected);
    }

    #[test]
    fn encryption_error_advises_against_retry() {
        let err = EncryptionError::MismatchedKeyInfo;
        assert!(!err.is_retryable());
        assert_eq!(
            huskarl_core::Error::from(err).retry_advice(),
            RetryAdvice::No
        );
    }

    #[rstest]
    // Matching `enc` and `kid` values select by key ID.
    #[case(
        Some("A256GCM"),
        Some("k1"),
        Some("k1"),
        Some(KeyMatchStrength::ByKeyId)
    )]
    // A matching `enc` with no requested `kid` selects by algorithm.
    #[case(Some("A256GCM"), None, Some("k1"), Some(KeyMatchStrength::ByAlgorithm))]
    // A matching `enc` with different `kid` values does not match.
    #[case(Some("A256GCM"), Some("k2"), Some("k1"), None)]
    // Different `enc` values do not match.
    #[case(Some("A128GCM"), None, None, None)]
    // No requested `enc` selects by algorithm.
    #[case(None, None, None, Some(KeyMatchStrength::ByAlgorithm))]
    fn cipher_match_applies_alg_and_kid_rules(
        #[case] req_enc: Option<&str>,
        #[case] req_kid: Option<&str>,
        #[case] registered_kid: Option<&str>,
        #[case] expected: Option<KeyMatchStrength>,
    ) {
        let kv = key_version(MockKms::default(), "A256GCM", registered_kid);
        let m = CipherMatch::builder()
            .maybe_enc(req_enc)
            .maybe_kid(req_kid)
            .build();
        assert_eq!(kv.cipher_match(&m), expected);
    }

    #[tokio::test]
    async fn encrypt_splits_tag_off_the_ciphertext() {
        let mock = MockKms {
            response_name: "projects/p/.../cryptoKeyVersions/1".to_owned(),
            // [ ciphertext (3) || tag (4) ], tag appended by KMS.
            ciphertext: vec![0xC0, 0xC1, 0xC2, 0xD0, 0xD1, 0xD2, 0xD3],
            tag_length: 4,
            iv: vec![0x9A, 0x9B],
        };
        let kv = key_version(mock, "A256GCM", None);

        let out = kv.encrypt(b"plaintext", b"aad").await.unwrap();
        assert_eq!(out.nonce, vec![0x9A, 0x9B]);
        assert_eq!(out.ciphertext, vec![0xC0, 0xC1, 0xC2]);
        assert_eq!(out.tag, vec![0xD0, 0xD1, 0xD2, 0xD3]);
    }

    #[tokio::test]
    async fn encrypt_rejects_mismatched_key_name() {
        let mock = MockKms {
            response_name: "projects/p/.../cryptoKeyVersions/2".to_owned(), // rotated under us
            ciphertext: vec![1, 2, 3, 4],
            tag_length: 1,
            iv: vec![0],
        };
        let kv = key_version(mock, "A256GCM", None);

        let err = kv.encrypt(b"plaintext", b"aad").await.err().unwrap();
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }

    #[tokio::test]
    async fn decrypt_appends_tag_to_ciphertext_for_kms() {
        let kv = key_version(MockKms::default(), "A256GCM", None);

        // The stub echoes back the buffer it received as plaintext.
        let echoed = kv
            .decrypt(None, b"nonce", &[0xAA, 0xBB], &[0xCC, 0xDD], b"aad")
            .await
            .unwrap();
        assert_eq!(echoed, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
