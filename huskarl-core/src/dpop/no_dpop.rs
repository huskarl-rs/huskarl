use http::{Method, Uri};
use snafu::Snafu;

use crate::{
    dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
    secrets::SecretString,
};

/// This represents a grant without the ability to use `DPoP` to constrain tokens.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDPoP;

impl super::sealed::Sealed for NoDPoP {}

/// This represents a situation where a `DPoP` proof is required, but the server is not configured to use `DPoP`.
#[derive(Debug, Clone, Copy, Default, Snafu)]
pub struct DPoPNotConfigured;

impl crate::Error for DPoPNotConfigured {
    fn is_retryable(&self) -> bool {
        false
    }
}

impl AuthorizationServerDPoP for NoDPoP {
    type Error = DPoPNotConfigured;
    type ResourceServerDPoP = NoDPoP;

    fn update_nonce(&self, _nonce: String) {}

    fn get_current_thumbprint(&self) -> Option<String> {
        None
    }

    async fn proof(
        &self,
        _method: &Method,
        _uri: &Uri,
        dpop_jkt: Option<&str>,
    ) -> Result<Option<SecretString>, Self::Error> {
        if dpop_jkt.is_some() {
            Err(DPoPNotConfigured)
        } else {
            Ok(None)
        }
    }

    fn to_resource_server_dpop(&self) -> Self::ResourceServerDPoP {
        NoDPoP
    }
}

impl ResourceServerDPoP for NoDPoP {
    type Error = DPoPNotConfigured;

    fn update_nonce(&self, _uri: &Uri, _nonce: String) {}

    async fn proof(
        &self,
        _method: &Method,
        _uri: &Uri,
        _access_token: &SecretString,
        _dpop_jkt: &str,
    ) -> Result<Option<SecretString>, Self::Error> {
        Err(DPoPNotConfigured)
    }
}
