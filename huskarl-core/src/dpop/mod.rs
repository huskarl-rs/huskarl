//! Demonstrating Proof-of-Possession (`DPoP`) support.
//!
//! Provides traits for creating `DPoP` proofs that bind tokens to a specific
//! client key pair. Separate traits handle the authorization server flow
//! (token acquisition with nonce management) and resource server flow
//! (proof creation bound to an access token).

mod implementation;
mod no_dpop;
mod sealed;

use std::sync::Arc;

use http::{Method, Uri};
pub use implementation::{
    DPoP, DPoPBuilder, ResourceDPoP, ResourceDPoPBuilder, hash_access_token_for_dpop,
    normalize_uri_for_dpop,
};
pub use no_dpop::{DPoPNotConfigured, NoDPoP};

use crate::{
    platform::{MaybeSend, MaybeSendSync},
    secrets::SecretString,
};

/// Proof implementation for `DPoP`.
pub trait AuthorizationServerDPoP: sealed::Sealed + Clone + MaybeSendSync {
    /// The error type when signing proofs.
    type Error: crate::Error;
    /// The type of the corresponding resource server variant.
    type ResourceServerDPoP: ResourceServerDPoP;

    /// Set the current `DPoP` nonce value.
    fn update_nonce(&self, nonce: String);

    /// Returns a signer to use with the [`Self::proof`] call.
    ///
    /// If a thumbprint has already been bound to the session, pass it here.
    fn get_current_thumbprint(&self) -> Option<String>;

    /// Create a `DPoP` proof for the token endpoint.
    fn proof(
        &self,
        method: &Method,
        uri: &Uri,
        dpop_jkt: Option<&str>,
    ) -> impl Future<Output = Result<Option<SecretString>, Self::Error>> + MaybeSend;

    /// Returns the corresponding resource server variant.
    fn to_resource_server_dpop(&self) -> Self::ResourceServerDPoP;
}

impl<D: AuthorizationServerDPoP> AuthorizationServerDPoP for Arc<D> {
    type Error = D::Error;

    type ResourceServerDPoP = D::ResourceServerDPoP;

    fn update_nonce(&self, nonce: String) {
        self.as_ref().update_nonce(nonce);
    }

    fn get_current_thumbprint(&self) -> Option<String> {
        self.as_ref().get_current_thumbprint()
    }

    async fn proof(
        &self,
        method: &Method,
        uri: &Uri,
        dpop_jkt: Option<&str>,
    ) -> Result<Option<SecretString>, Self::Error> {
        self.as_ref().proof(method, uri, dpop_jkt).await
    }

    fn to_resource_server_dpop(&self) -> Self::ResourceServerDPoP {
        self.as_ref().to_resource_server_dpop()
    }
}

/// Proof implementation for `DPoP` when calling resource servers.
pub trait ResourceServerDPoP: sealed::Sealed + MaybeSendSync {
    /// The error type when signing proofs;
    type Error: crate::Error;

    /// Set the current `DPoP` nonce value.
    fn update_nonce(&self, uri: &Uri, nonce: String);

    /// Create a `DPoP` proof with access token binding.
    fn proof(
        &self,
        method: &Method,
        uri: &Uri,
        access_token: &SecretString,
        dpop_jkt: &str,
    ) -> impl Future<Output = Result<Option<SecretString>, Self::Error>> + MaybeSend;
}
