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
    crypto::signer::{BoxedAsymmetricJwsSigningKey, HasPublicKey, JwsSigningKey},
    dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
    jwt::{JwsSerializationError, Jwt},
    secrets::SecretString,
    token::AccessToken,
};

// Used internally to track the origin value for a Uri (nonces are matched by origin).
type Origin = (Option<Scheme>, Option<String>, Option<u16>);

/// This respresents a grant with the ability to create DPoP-bound tokens and sign requests with them.
#[derive(Debug, Clone, Builder)]
pub struct DPoP<Sgn: JwsSigningKey + HasPublicKey = BoxedAsymmetricJwsSigningKey> {
    signer: Sgn,
    #[builder(skip = signer.public_key_jwk().thumbprint())]
    jwk_thumbprint: Option<String>,
    #[builder(skip)]
    nonce: Arc<Mutex<Option<Arc<String>>>>,
}

impl<Sgn: JwsSigningKey + HasPublicKey + Clone> AuthorizationServerDPoP for DPoP<Sgn> {
    type Error = JwsSerializationError<<Sgn as JwsSigningKey>::Error>;
    type ResourceServerDPoP = ResourceDPoP<Sgn>;

    fn jwk_thumbprint(&self) -> Option<&str> {
        self.jwk_thumbprint.as_deref()
    }

    fn update_nonce(&self, nonce: String) {
        let _ = self.nonce.lock().unwrap().insert(Arc::new(nonce));
    }

    async fn proof(&self, method: &Method, uri: &Uri) -> Result<Option<SecretString>, Self::Error> {
        let nonce = self.nonce.lock().unwrap().clone();
        sign_proof(&self.signer, method, uri, None, nonce).await
    }

    fn to_resource_server_dpop(&self) -> Self::ResourceServerDPoP {
        ResourceDPoP::builder().signer(self.signer.clone()).build()
    }
}

/// This respresents the ability to create proofs for resource servers from DPoP-bound access tokens.
#[derive(Debug, Clone, Builder)]
pub struct ResourceDPoP<Sgn: JwsSigningKey + HasPublicKey> {
    signer: Sgn,
    #[builder(default)]
    nonces: Arc<RwLock<HashMap<Origin, Arc<String>>>>,
}

impl<Sgn: JwsSigningKey + HasPublicKey> ResourceServerDPoP for ResourceDPoP<Sgn> {
    type Error = JwsSerializationError<<Sgn as JwsSigningKey>::Error>;

    fn update_nonce(&self, uri: &Uri, nonce: String) {
        let origin = origin_from_uri(uri);
        self.nonces.write().unwrap().insert(origin, Arc::new(nonce));
    }

    async fn proof(
        &self,
        method: &Method,
        uri: &Uri,
        access_token: &AccessToken,
    ) -> Result<Option<SecretString>, Self::Error> {
        let origin = origin_from_uri(uri);
        let nonce = self.nonces.read().unwrap().get(&origin).cloned();
        sign_proof(&self.signer, method, uri, Some(access_token), nonce).await
    }
}

fn origin_from_uri(uri: &Uri) -> Origin {
    (
        uri.scheme().cloned(),
        uri.host().map(str::to_string),
        uri.port_u16(),
    )
}

async fn sign_proof<Sgn: JwsSigningKey + HasPublicKey>(
    signer: &Sgn,
    htm: &Method,
    htu: &Uri,
    access_token: Option<&AccessToken>,
    nonce: Option<Arc<String>>,
) -> Result<Option<SecretString>, JwsSerializationError<<Sgn as JwsSigningKey>::Error>> {
    #[derive(Debug, Clone, Serialize)]
    struct DPoPHeaders {
        jwk: serde_json::Value,
    }

    #[derive(Debug, Clone, Serialize)]
    struct DPoPClaims<'a> {
        htm: &'a str,
        htu: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ath: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<Arc<String>>,
    }

    let extra_headers = DPoPHeaders {
        jwk: serde_json::to_value(signer.public_key_jwk())
            .expect("PublicJwk serialization cannot fail"),
    };

    let extra_claims = DPoPClaims {
        htm: htm.as_str(),
        htu: normalize_uri_for_dpop(htu).unwrap().to_string(),
        ath: access_token.map(hash_access_token_for_dpop),
        nonce,
    };

    let jwt = Jwt::builder()
        .typ("dpop+jwt")
        .issued_now_expires_after(Duration::from_secs(60))
        .extra_headers(extra_headers)
        .extra_claims(extra_claims)
        .build();

    jwt.to_jws_compact(signer).await.map(Some)
}

fn normalize_uri_for_dpop(uri: &Uri) -> Result<Uri, http::Error> {
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

fn hash_access_token_for_dpop(access_token: &AccessToken) -> String {
    let mut hasher = Sha256::new();
    hasher.update(access_token.expose_token().as_bytes());
    let hash_digest = hasher.finalize();
    BASE64_URL_SAFE_NO_PAD.encode(hash_digest)
}
