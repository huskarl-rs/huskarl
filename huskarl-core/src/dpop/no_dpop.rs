use std::convert::Infallible;

use http::{Method, Uri};

use crate::{
    dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
    secrets::SecretString,
    token::AccessToken,
};

/// This represents a grant without the ability to use `DPoP` to constrain tokens.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDPoP;

impl AuthorizationServerDPoP for NoDPoP {
    type Error = Infallible;
    type ResourceServerDPoP = NoDPoP;

    fn jwk_thumbprint(&self) -> Option<&str> {
        None
    }

    fn update_nonce(&self, _nonce: String) {}

    async fn proof(
        &self,
        _method: &Method,
        _uri: &Uri,
    ) -> Result<Option<SecretString>, Self::Error> {
        Ok(None)
    }

    fn to_resource_server_dpop(&self) -> Self::ResourceServerDPoP {
        NoDPoP
    }
}

impl ResourceServerDPoP for NoDPoP {
    type Error = Infallible;

    fn update_nonce(&self, _uri: &Uri, _nonce: String) {}

    async fn proof(
        &self,
        _method: &Method,
        _uri: &Uri,
        _access_token: &AccessToken,
    ) -> Result<Option<SecretString>, Self::Error> {
        Ok(None)
    }
}
