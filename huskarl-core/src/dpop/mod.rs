//! Demonstrating Proof-of-Possession (`DPoP`) support.
//!
//! Provides traits for creating `DPoP` proofs that bind tokens to a specific
//! client key pair. Separate traits handle the authorization server flow
//! (token acquisition with nonce management) and resource server flow
//! (proof creation bound to an access token). The server side of nonce
//! management lives here too: [`DPoPNonceChecker`] issues and validates the
//! nonces (RFC 9449 §8) that proofs must echo.

mod implementation;
mod no_dpop;
mod nonce;
mod sealed;

use std::sync::Arc;

use http::{Method, Uri};
pub use implementation::{
    DPoP, DPoPBuilder, ResourceDPoP, ResourceDPoPBuilder, SessionKeyedDPoP,
    hash_access_token_for_dpop, normalize_uri_for_dpop,
};
pub use no_dpop::{DPoPNotConfigured, NoDPoP};
pub use nonce::{DPoPNonceChecker, NonceCheck, SealedTimestampNonce, SealedTimestampNonceBuilder};

use crate::{
    crypto::signer::AsymmetricJwsSignerSelector,
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
    secrets::SecretString,
};

/// Proof implementation for `DPoP`.
///
/// This trait is dyn-capable: grants store it as
/// `Arc<dyn AuthorizationServerDPoP>`.
pub trait AuthorizationServerDPoP: sealed::Sealed + MaybeSendSync {
    /// Set the current `DPoP` nonce value.
    fn update_nonce(&self, nonce: String);

    /// Returns the thumbprint of the current signing key, to bind to the session.
    ///
    /// This is **async**: for a refreshing signer it selects (and so may reload)
    /// the current key, keeping the bound thumbprint consistent with the key that
    /// will later sign proofs.
    fn get_current_thumbprint(&self) -> MaybeSendBoxFuture<'_, Option<String>>;

    /// Create a `DPoP` proof for the token endpoint.
    fn proof<'a>(
        &'a self,
        method: &'a Method,
        uri: &'a Uri,
        dpop_jkt: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>>;

    /// Returns the corresponding resource server variant.
    fn to_resource_server_dpop(&self) -> Arc<dyn ResourceServerDPoP>;

    /// Binds a per-session signing key, sharing this instance's server-scoped
    /// nonce.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is a [`SessionKeyedDPoP`]; a fixed-key
    /// [`DPoP`] or [`NoDPoP`] rejects the override rather than silently
    /// accepting it.
    fn with_session_key(
        &self,
        signer: Arc<dyn AsymmetricJwsSignerSelector>,
    ) -> Result<Arc<dyn AuthorizationServerDPoP>, Error>;
}

/// Proof implementation for `DPoP` when calling resource servers.
///
/// This trait is dyn-capable: authorizers store it as
/// `Arc<dyn ResourceServerDPoP>`.
pub trait ResourceServerDPoP: sealed::Sealed + MaybeSendSync {
    /// Set the current `DPoP` nonce value.
    fn update_nonce(&self, uri: &Uri, nonce: String);

    /// Create a `DPoP` proof with access token binding.
    fn proof<'a>(
        &'a self,
        method: &'a Method,
        uri: &'a Uri,
        access_token: &'a SecretString,
        dpop_jkt: &'a str,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>>;
}

impl<T: AuthorizationServerDPoP + ?Sized> AuthorizationServerDPoP for &T {
    fn update_nonce(&self, nonce: String) {
        (**self).update_nonce(nonce);
    }

    fn get_current_thumbprint(&self) -> MaybeSendBoxFuture<'_, Option<String>> {
        (**self).get_current_thumbprint()
    }

    fn proof<'a>(
        &'a self,
        method: &'a Method,
        uri: &'a Uri,
        dpop_jkt: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        (**self).proof(method, uri, dpop_jkt)
    }

    fn to_resource_server_dpop(&self) -> Arc<dyn ResourceServerDPoP> {
        (**self).to_resource_server_dpop()
    }

    fn with_session_key(
        &self,
        signer: Arc<dyn AsymmetricJwsSignerSelector>,
    ) -> Result<Arc<dyn AuthorizationServerDPoP>, Error> {
        (**self).with_session_key(signer)
    }
}

impl<T: AuthorizationServerDPoP + ?Sized> AuthorizationServerDPoP for Box<T> {
    fn update_nonce(&self, nonce: String) {
        (**self).update_nonce(nonce);
    }

    fn get_current_thumbprint(&self) -> MaybeSendBoxFuture<'_, Option<String>> {
        (**self).get_current_thumbprint()
    }

    fn proof<'a>(
        &'a self,
        method: &'a Method,
        uri: &'a Uri,
        dpop_jkt: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        (**self).proof(method, uri, dpop_jkt)
    }

    fn to_resource_server_dpop(&self) -> Arc<dyn ResourceServerDPoP> {
        (**self).to_resource_server_dpop()
    }

    fn with_session_key(
        &self,
        signer: Arc<dyn AsymmetricJwsSignerSelector>,
    ) -> Result<Arc<dyn AuthorizationServerDPoP>, Error> {
        (**self).with_session_key(signer)
    }
}

impl<T: AuthorizationServerDPoP + ?Sized> AuthorizationServerDPoP for Arc<T> {
    fn update_nonce(&self, nonce: String) {
        (**self).update_nonce(nonce);
    }

    fn get_current_thumbprint(&self) -> MaybeSendBoxFuture<'_, Option<String>> {
        (**self).get_current_thumbprint()
    }

    fn proof<'a>(
        &'a self,
        method: &'a Method,
        uri: &'a Uri,
        dpop_jkt: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        (**self).proof(method, uri, dpop_jkt)
    }

    fn to_resource_server_dpop(&self) -> Arc<dyn ResourceServerDPoP> {
        (**self).to_resource_server_dpop()
    }

    fn with_session_key(
        &self,
        signer: Arc<dyn AsymmetricJwsSignerSelector>,
    ) -> Result<Arc<dyn AuthorizationServerDPoP>, Error> {
        (**self).with_session_key(signer)
    }
}

impl<T: ResourceServerDPoP + ?Sized> ResourceServerDPoP for &T {
    fn update_nonce(&self, uri: &Uri, nonce: String) {
        (**self).update_nonce(uri, nonce);
    }

    fn proof<'a>(
        &'a self,
        method: &'a Method,
        uri: &'a Uri,
        access_token: &'a SecretString,
        dpop_jkt: &'a str,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        (**self).proof(method, uri, access_token, dpop_jkt)
    }
}

impl<T: ResourceServerDPoP + ?Sized> ResourceServerDPoP for Box<T> {
    fn update_nonce(&self, uri: &Uri, nonce: String) {
        (**self).update_nonce(uri, nonce);
    }

    fn proof<'a>(
        &'a self,
        method: &'a Method,
        uri: &'a Uri,
        access_token: &'a SecretString,
        dpop_jkt: &'a str,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        (**self).proof(method, uri, access_token, dpop_jkt)
    }
}

impl<T: ResourceServerDPoP + ?Sized> ResourceServerDPoP for Arc<T> {
    fn update_nonce(&self, uri: &Uri, nonce: String) {
        (**self).update_nonce(uri, nonce);
    }

    fn proof<'a>(
        &'a self,
        method: &'a Method,
        uri: &'a Uri,
        access_token: &'a SecretString,
        dpop_jkt: &'a str,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        (**self).proof(method, uri, access_token, dpop_jkt)
    }
}
