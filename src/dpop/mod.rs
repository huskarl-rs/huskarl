//! Demonstrating Proof-of-Possession (`DPoP`) support.
//!
//! Provides traits for creating `DPoP` proofs that bind tokens to a specific
//! client key pair. Separate traits handle the authorization server flow
//! (token acquisition with nonce management) and resource server flow
//! (proof creation bound to an access token).

mod implementation;
mod no_dpop;

use std::sync::Arc;

use http::{Method, Uri};

use crate::{
    platform::{MaybeSend, MaybeSendSync},
    secrets::SecretString,
    token::AccessToken,
};

pub use implementation::{DPoP, DPoPBuilder, ResourceDPoP, ResourceDPoPBuilder};
pub use no_dpop::NoDPoP;

/// Proof implementation for `DPoP`.
pub trait AuthorizationServerDPoP: MaybeSendSync {
    /// The error type when signing proofs.
    type Error: crate::Error;
    /// The type of the corresponding resource server variant.
    type ResourceServerDPoP: ResourceServerDPoP;

    /// Returns the JWK thumbprint for the public key.
    fn jwk_thumbprint(&self) -> Option<&str>;

    /// Set the current `DPoP` nonce value.
    fn update_nonce(&self, nonce: String);

    /// Create a `DPoP` proof for the token endpoint.
    fn proof(
        &self,
        method: &Method,
        uri: &Uri,
    ) -> impl Future<Output = Result<Option<SecretString>, Self::Error>> + MaybeSend;

    /// Returns the corresponding resource server variant.
    fn to_resource_server_dpop(&self) -> Self::ResourceServerDPoP;
}

impl<D: AuthorizationServerDPoP> AuthorizationServerDPoP for Arc<D> {
    type Error = D::Error;

    type ResourceServerDPoP = D::ResourceServerDPoP;

    fn jwk_thumbprint(&self) -> Option<&str> {
        self.as_ref().jwk_thumbprint()
    }

    fn update_nonce(&self, nonce: String) {
        self.as_ref().update_nonce(nonce);
    }

    async fn proof(&self, method: &Method, uri: &Uri) -> Result<Option<SecretString>, Self::Error> {
        self.as_ref().proof(method, uri).await
    }

    fn to_resource_server_dpop(&self) -> Self::ResourceServerDPoP {
        self.as_ref().to_resource_server_dpop()
    }
}

/// Proof implementation for `DPoP` when calling resource servers.
pub trait ResourceServerDPoP: MaybeSendSync {
    /// The error type when signing proofs;
    type Error: crate::Error;

    /// Set the current `DPoP` nonce value.
    fn update_nonce(&self, uri: &Uri, nonce: String);

    /// Create a `DPoP` proof with access token binding.
    fn proof(
        &self,
        method: &Method,
        uri: &Uri,
        access_token: &AccessToken,
    ) -> impl Future<Output = Result<Option<SecretString>, Self::Error>> + MaybeSend;
}
