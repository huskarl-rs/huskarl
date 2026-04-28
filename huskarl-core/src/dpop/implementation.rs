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
    crypto::signer::{
        AsymmetricJwsSigner, AsymmetricJwsSignerSelector, BoxedAsymmetricJwsSignerSelector,
        JwsSigner,
    },
    dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
    jwt::{JwsSerializationError, Jwt},
    secrets::SecretString,
};

// Used internally to track the origin value for a Uri (nonces are matched by origin).
type Origin = (Option<Scheme>, Option<String>, Option<u16>);

/// This respresents a grant with the ability to create DPoP-bound tokens and sign requests with them.
#[derive(Debug, Clone, Builder)]
pub struct DPoP<Sgn: AsymmetricJwsSignerSelector = BoxedAsymmetricJwsSignerSelector> {
    signer: Sgn,
    #[builder(skip)]
    nonce: Arc<Mutex<Option<Arc<String>>>>,
}

impl<Sgn: AsymmetricJwsSignerSelector> AuthorizationServerDPoP for DPoP<Sgn> {
    type Error = JwsSerializationError<<Sgn::AsymmetricSigner as JwsSigner>::Error>;
    type ResourceServerDPoP = ResourceDPoP<Sgn>;

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
        self.signer
            .select_asymmetric_signer()
            .public_key_jwk()
            .thumbprint()
    }

    async fn proof(
        &self,
        method: &Method,
        uri: &Uri,
        dpop_jkt: Option<&str>,
    ) -> Result<Option<SecretString>, Self::Error> {
        // See comment in `update_nonce` for why poison recovery is intentional here.
        let nonce = self
            .nonce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();

        let Some(dpop_jkt) = dpop_jkt else {
            return Err(JwsSerializationError::NoThumbprint);
        };

        let signer = self
            .signer
            .select_asymmetric_signer_by_thumbprint(dpop_jkt)
            .ok_or(JwsSerializationError::NoMatchingKeyForThumbprint)?;

        sign_proof(&signer, method, uri, None, nonce).await
    }

    fn to_resource_server_dpop(&self) -> Self::ResourceServerDPoP {
        ResourceDPoP::builder().signer(self.signer.clone()).build()
    }
}

/// This respresents the ability to create proofs for resource servers from DPoP-bound access tokens.
#[derive(Debug, Clone, Builder)]
pub struct ResourceDPoP<Sgn: AsymmetricJwsSignerSelector> {
    signer: Sgn,
    #[builder(default)]
    nonces: Arc<RwLock<HashMap<Origin, Arc<String>>>>,
}

impl<Sgn: AsymmetricJwsSignerSelector> ResourceServerDPoP for ResourceDPoP<Sgn> {
    type Error = JwsSerializationError<<Sgn::AsymmetricSigner as JwsSigner>::Error>;

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

    async fn proof(
        &self,
        method: &Method,
        uri: &Uri,
        access_token: &SecretString,
        dpop_jkt: &str,
    ) -> Result<Option<SecretString>, Self::Error> {
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
            .select_asymmetric_signer_by_thumbprint(dpop_jkt)
            .ok_or(JwsSerializationError::NoMatchingKeyForThumbprint)?;

        sign_proof(
            &signer,
            method,
            uri,
            Some(access_token.expose_secret()),
            nonce,
        )
        .await
    }
}

fn origin_from_uri(uri: &Uri) -> Origin {
    (
        uri.scheme().cloned(),
        uri.host().map(str::to_string),
        uri.port_u16(),
    )
}

async fn sign_proof<Sgn: AsymmetricJwsSigner>(
    signer: &Sgn,
    htm: &Method,
    htu: &Uri,
    token: Option<&str>,
    nonce: Option<Arc<String>>,
) -> Result<Option<SecretString>, JwsSerializationError<Sgn::Error>> {
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
            .map_err(|source| JwsSerializationError::NormalizeUri { source })?
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
