use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use base64::prelude::*;
use bon::Builder;
use http::{Method, Uri, uri::Scheme};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    crypto::signer::{AsymmetricJwsSigner, AsymmetricJwsSignerSelector},
    dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
    error::{Error, ErrorKind},
    jwt::Jwt,
    platform::MaybeSendBoxFuture,
    secrets::SecretString,
};

// Used internally to track the origin value for a Uri (nonces are matched by origin).
type Origin = (Option<Scheme>, Option<String>, Option<u16>);

impl super::sealed::Sealed for DPoP {}

/// This respresents a grant with the ability to create DPoP-bound tokens and sign requests with them.
#[derive(Debug, Clone, Builder)]
pub struct DPoP {
    #[builder(with = |signer: impl AsymmetricJwsSignerSelector + 'static| Arc::new(signer) as Arc<dyn AsymmetricJwsSignerSelector>)]
    signer: Arc<dyn AsymmetricJwsSignerSelector>,
    #[builder(skip)]
    nonce: Arc<Mutex<Option<Arc<String>>>>,
}

impl AuthorizationServerDPoP for DPoP {
    fn update_nonce(&self, nonce: String) {
        // If the lock is poisoned (a thread panicked while holding it), we recover
        // the guard and proceed. A stale nonce just causes the server to reject the
        // next DPoP proof and return a fresh nonce, so the worst case is one extra
        // round-trip rather than a hard failure.
        let _ = self
            .nonce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(Arc::new(nonce));
    }

    fn get_current_thumbprint(&self) -> Option<String> {
        Some(
            self.signer
                .select_asymmetric_signer()
                .public_key_jwk()
                .thumbprint(),
        )
    }

    fn proof<'a>(
        &'a self,
        method: &'a Method,
        uri: &'a Uri,
        dpop_jkt: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        Box::pin(async move {
            // See comment in `update_nonce` for why poison recovery is intentional here.
            let nonce = self
                .nonce
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();

            let Some(dpop_jkt) = dpop_jkt else {
                return Err(no_thumbprint_error());
            };

            let signer = self
                .signer
                .select_signer_by_thumbprint(dpop_jkt)
                .ok_or_else(no_matching_key_error)?;

            sign_proof(&*signer, method, uri, None, nonce).await
        })
    }

    fn to_resource_server_dpop(&self) -> Arc<dyn ResourceServerDPoP> {
        Arc::new(ResourceDPoP {
            signer: self.signer.clone(),
            nonces: Arc::default(),
        })
    }
}

impl super::sealed::Sealed for ResourceDPoP {}

/// This respresents the ability to create proofs for resource servers from DPoP-bound access tokens.
#[derive(Debug, Clone, Builder)]
pub struct ResourceDPoP {
    #[builder(with = |signer: impl AsymmetricJwsSignerSelector + 'static| Arc::new(signer) as Arc<dyn AsymmetricJwsSignerSelector>)]
    signer: Arc<dyn AsymmetricJwsSignerSelector>,
    #[builder(default)]
    nonces: Arc<RwLock<HashMap<Origin, Arc<String>>>>,
}

impl ResourceServerDPoP for ResourceDPoP {
    fn update_nonce(&self, uri: &Uri, nonce: String) {
        let origin = origin_from_uri(uri);
        // If the lock is poisoned (a thread panicked while holding it), we recover
        // the guard and proceed. A stale nonce just causes the server to reject the
        // next DPoP proof and return a fresh nonce, so the worst case is one extra
        // round-trip rather than a hard failure.
        self.nonces
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(origin, Arc::new(nonce));
    }

    fn proof<'a>(
        &'a self,
        method: &'a Method,
        uri: &'a Uri,
        access_token: &'a SecretString,
        dpop_jkt: &'a str,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        Box::pin(async move {
            let origin = origin_from_uri(uri);
            // See comment in `update_nonce` for why poison recovery is intentional here.
            let nonce = self
                .nonces
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&origin)
                .cloned();

            let signer = self
                .signer
                .select_signer_by_thumbprint(dpop_jkt)
                .ok_or_else(no_matching_key_error)?;

            sign_proof(
                &*signer,
                method,
                uri,
                Some(access_token.expose_secret()),
                nonce,
            )
            .await
        })
    }
}

/// No JWK thumbprint provided for proof.
///
/// This indicates a logic error; the caller should provide a thumbprint
/// when `DPoP` is configured.
fn no_thumbprint_error() -> Error {
    Error::from(ErrorKind::Dpop).with_context("no JWK thumbprint provided for proof")
}

fn no_matching_key_error() -> Error {
    Error::from(ErrorKind::Dpop).with_context("no matching key for the given thumbprint")
}

fn origin_from_uri(uri: &Uri) -> Origin {
    (
        uri.scheme().cloned(),
        uri.host().map(str::to_string),
        uri.port_u16(),
    )
}

async fn sign_proof(
    signer: &dyn AsymmetricJwsSigner,
    htm: &Method,
    htu: &Uri,
    token: Option<&str>,
    nonce: Option<Arc<String>>,
) -> Result<Option<SecretString>, Error> {
    #[derive(Debug, Clone, Serialize)]
    struct DPoPClaims<'a> {
        htm: &'a str,
        htu: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ath: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<Arc<String>>,
    }

    let extra_claims = DPoPClaims {
        htm: htm.as_str(),
        htu: normalize_uri_for_dpop(htu)
            .map_err(|source| {
                Error::new(ErrorKind::Dpop, source).with_context("normalizing URI for DPoP proof")
            })?
            .to_string(),
        ath: token.map(hash_access_token_for_dpop),
        nonce,
    };

    let jwt = Jwt::builder()
        .typ("dpop+jwt")
        .issued_now_expires_after(Duration::from_mins(1))
        .jwk(signer.public_key_jwk().into_owned())
        .claims(extra_claims)
        .build();

    jwt.to_jws_compact(signer).await.map(Some)
}

/// Normalizes a URI for inclusion in a `DPoP` proof by stripping query and fragment components.
///
/// # Errors
///
/// Returns an error if the resulting URI cannot be constructed (e.g. invalid authority).
pub fn normalize_uri_for_dpop(uri: &Uri) -> Result<Uri, http::Error> {
    let mut builder = http::uri::Builder::new();

    if let Some(scheme) = uri.scheme() {
        builder = builder.scheme(scheme.clone());
    }
    if let Some(authority) = uri.authority() {
        builder = builder.authority(authority.clone());
    }
    builder = builder.path_and_query(uri.path());
    builder.build()
}

/// Computes the SHA-256 `ath` hash of an access token for inclusion in a `DPoP` proof.
#[must_use]
pub fn hash_access_token_for_dpop(access_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    let hash_digest = hasher.finalize();
    BASE64_URL_SAFE_NO_PAD.encode(hash_digest)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::{
        crypto::signer::{
            AsymmetricJwsSigner, AsymmetricJwsSignerSelector, JwsSigner, JwsSignerSelector,
        },
        dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
        jwk::{EcPublicKey, PublicJwk},
        platform::MaybeSendBoxFuture,
    };

    fn mock_public_jwk() -> PublicJwk {
        PublicJwk::builder()
            .key(
                EcPublicKey::builder()
                    .crv("P-256")
                    .x([1u8; 32])
                    .y([2u8; 32])
                    .build(),
            )
            .build()
    }

    #[derive(Debug, Clone)]
    struct MockAsymmetricJwsSigner {
        jwk: PublicJwk,
    }

    impl JwsSigner for MockAsymmetricJwsSigner {
        fn jws_algorithm(&self) -> Cow<'_, str> {
            "ES256".into()
        }
        fn key_id(&self) -> Option<Cow<'_, str>> {
            None
        }
        fn sign<'a>(&'a self, _input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
            Box::pin(async { Ok(vec![0xCA, 0xFE]) })
        }
    }

    impl AsymmetricJwsSigner for MockAsymmetricJwsSigner {
        fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
            Cow::Borrowed(&self.jwk)
        }
    }

    impl JwsSignerSelector for MockAsymmetricJwsSigner {
        fn select_signer(&self) -> Arc<dyn JwsSigner> {
            self.select_asymmetric_signer()
        }
    }

    impl AsymmetricJwsSignerSelector for MockAsymmetricJwsSigner {
        fn select_asymmetric_signer(&self) -> Arc<dyn AsymmetricJwsSigner> {
            Arc::new(self.clone())
        }

        fn select_signer_by_thumbprint(
            &self,
            thumbprint: &str,
        ) -> Option<Arc<dyn AsymmetricJwsSigner>> {
            if thumbprint == self.jwk.thumbprint() {
                Some(Arc::new(self.clone()))
            } else {
                None
            }
        }
    }

    // --- normalize_uri_for_dpop ---

    #[test]
    fn normalize_uri_strips_query_and_fragment() {
        let uri: Uri = "https://example.com/path?query=1#frag".parse().unwrap();
        let normalized = normalize_uri_for_dpop(&uri).unwrap();
        assert_eq!(normalized.to_string(), "https://example.com/path");
    }

    #[test]
    fn normalize_uri_passthrough() {
        let uri: Uri = "https://example.com/path".parse().unwrap();
        let normalized = normalize_uri_for_dpop(&uri).unwrap();
        assert_eq!(normalized.to_string(), "https://example.com/path");
    }

    #[test]
    fn normalize_uri_scheme_and_authority_only() {
        let uri: Uri = "https://example.com".parse().unwrap();
        let normalized = normalize_uri_for_dpop(&uri).unwrap();
        assert_eq!(normalized.to_string(), "https://example.com/");
    }

    // --- hash_access_token_for_dpop ---

    #[test]
    fn hash_access_token_known_value() {
        // SHA-256 of "test-token" = known value
        let hash = hash_access_token_for_dpop("test-token");
        // Verify it's a valid base64url string of 32 bytes
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&hash).unwrap();
        assert_eq!(decoded.len(), 32);

        // Same input always produces same output
        assert_eq!(hash, hash_access_token_for_dpop("test-token"));
        // Different input produces different output
        assert_ne!(hash, hash_access_token_for_dpop("other-token"));
    }

    // --- DPoP::proof ---

    #[tokio::test]
    async fn dpop_proof_success() {
        let jwk = mock_public_jwk();
        let thumbprint = jwk.thumbprint();
        let signer = MockAsymmetricJwsSigner { jwk };
        let dpop = DPoP::builder().signer(signer).build();

        let uri: Uri = "https://auth.example.com/token?foo=bar".parse().unwrap();
        let result = dpop
            .proof(&Method::POST, &uri, Some(&thumbprint))
            .await
            .unwrap();

        let token = result.unwrap();
        let parts: Vec<&str> = token.expose_secret().split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode header
        let header: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert!(header.get("jwk").is_some());

        // Decode claims
        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["htm"], "POST");
        // htu should not have query string
        let htu = claims["htu"].as_str().unwrap();
        assert!(!htu.contains('?'));
        assert!(htu.starts_with("https://auth.example.com"));
        assert!(claims.get("jti").is_some());
        assert!(claims.get("iat").is_some());
        assert!(claims.get("exp").is_some());
    }

    #[tokio::test]
    async fn dpop_proof_no_thumbprint() {
        let signer = MockAsymmetricJwsSigner {
            jwk: mock_public_jwk(),
        };
        let dpop = DPoP::builder().signer(signer).build();
        let uri: Uri = "https://auth.example.com/token".parse().unwrap();

        let err = dpop.proof(&Method::POST, &uri, None).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Dpop);
        assert!(err.to_string().contains("no JWK thumbprint"));
    }

    #[tokio::test]
    async fn dpop_proof_wrong_thumbprint() {
        let signer = MockAsymmetricJwsSigner {
            jwk: mock_public_jwk(),
        };
        let dpop = DPoP::builder().signer(signer).build();
        let uri: Uri = "https://auth.example.com/token".parse().unwrap();

        let err = dpop
            .proof(&Method::POST, &uri, Some("wrong-thumbprint"))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Dpop);
        assert!(err.to_string().contains("no matching key"));
    }

    #[tokio::test]
    async fn dpop_proof_with_nonce() {
        let jwk = mock_public_jwk();
        let thumbprint = jwk.thumbprint();
        let signer = MockAsymmetricJwsSigner { jwk };
        let dpop = DPoP::builder().signer(signer).build();

        dpop.update_nonce("server-nonce-123".into());

        let uri: Uri = "https://auth.example.com/token".parse().unwrap();
        let result = dpop
            .proof(&Method::POST, &uri, Some(&thumbprint))
            .await
            .unwrap();
        let token = result.unwrap();
        let parts: Vec<&str> = token.expose_secret().split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["nonce"], "server-nonce-123");
    }

    // --- ResourceDPoP ---

    #[tokio::test]
    async fn resource_dpop_proof_has_ath() {
        let jwk = mock_public_jwk();
        let thumbprint = jwk.thumbprint();
        let signer = MockAsymmetricJwsSigner { jwk };
        let dpop = DPoP::builder().signer(signer).build();
        let resource_dpop = dpop.to_resource_server_dpop();

        let uri: Uri = "https://api.example.com/resource".parse().unwrap();
        let access_token = SecretString::new("my-access-token");

        let result = resource_dpop
            .proof(&Method::GET, &uri, &access_token, &thumbprint)
            .await
            .unwrap();
        let token = result.unwrap();
        let parts: Vec<&str> = token.expose_secret().split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert!(claims.get("ath").is_some());
        // Verify ath matches hash of access token
        assert_eq!(claims["ath"], hash_access_token_for_dpop("my-access-token"));
    }

    #[tokio::test]
    async fn resource_dpop_per_origin_nonce() {
        let jwk = mock_public_jwk();
        let thumbprint = jwk.thumbprint();
        let signer = MockAsymmetricJwsSigner { jwk };
        let dpop = DPoP::builder().signer(signer).build();
        let resource_dpop = dpop.to_resource_server_dpop();

        let uri1: Uri = "https://api1.example.com/resource".parse().unwrap();
        let uri2: Uri = "https://api2.example.com/resource".parse().unwrap();

        resource_dpop.update_nonce(&uri1, "nonce-1".into());
        resource_dpop.update_nonce(&uri2, "nonce-2".into());

        let at = SecretString::new("token");

        let result1 = resource_dpop
            .proof(&Method::GET, &uri1, &at, &thumbprint)
            .await
            .unwrap()
            .unwrap();
        let parts1: Vec<&str> = result1.expose_secret().split('.').collect();
        let claims1: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts1[1]).unwrap()).unwrap();
        assert_eq!(claims1["nonce"], "nonce-1");

        let result2 = resource_dpop
            .proof(&Method::GET, &uri2, &at, &thumbprint)
            .await
            .unwrap()
            .unwrap();
        let parts2: Vec<&str> = result2.expose_secret().split('.').collect();
        let claims2: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts2[1]).unwrap()).unwrap();
        assert_eq!(claims2["nonce"], "nonce-2");
    }
}
