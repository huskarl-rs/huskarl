use std::sync::Arc;

use http::{Method, Uri};
use snafu::Snafu;

use crate::{
    crypto::signer::AsymmetricJwsSignerSelector,
    dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
    error::Error,
    platform::MaybeSendBoxFuture,
    secrets::SecretString,
};

/// The no-op `DPoP` implementation, used when `DPoP` is disabled — tokens are
/// not sender-constrained.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDPoP;

impl super::sealed::Sealed for NoDPoP {}

/// A `DPoP` proof was required, but `DPoP` is not configured.
#[derive(Debug, Clone, Copy, Default, Snafu)]
pub struct DPoPNotConfigured;

impl AuthorizationServerDPoP for NoDPoP {
    fn update_nonce(&self, _nonce: String) {}

    fn get_current_thumbprint(&self) -> MaybeSendBoxFuture<'_, Option<String>> {
        Box::pin(async { None })
    }

    fn proof<'a>(
        &'a self,
        _method: &'a Method,
        _uri: &'a Uri,
        dpop_jkt: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        Box::pin(async move {
            if dpop_jkt.is_some() {
                Err(DPoPNotConfiguredSnafu.build().into())
            } else {
                Ok(None)
            }
        })
    }

    fn to_resource_server_dpop(&self) -> Arc<dyn ResourceServerDPoP> {
        Arc::new(NoDPoP)
    }

    fn with_session_key(
        &self,
        _signer: Arc<dyn AsymmetricJwsSignerSelector>,
    ) -> Result<Arc<dyn AuthorizationServerDPoP>, Error> {
        // DPoP is disabled here; a per-session key needs SessionKeyedDPoP.
        Err(super::implementation::DPoPKeyError::DPoPNotEnabled.into())
    }
}

impl ResourceServerDPoP for NoDPoP {
    fn update_nonce(&self, _uri: &Uri, _nonce: String) {}

    fn proof<'a>(
        &'a self,
        _method: &'a Method,
        _uri: &'a Uri,
        _access_token: &'a SecretString,
        _dpop_jkt: &'a str,
    ) -> MaybeSendBoxFuture<'a, Result<Option<SecretString>, Error>> {
        Box::pin(async { Err(DPoPNotConfiguredSnafu.build().into()) })
    }
}

// This single-shape cause always establishes a terminal classification.
impl crate::error::propagation::Cause for DPoPNotConfigured {
    fn origin(&self) -> crate::error::propagation::Origin<'_> {
        crate::error::propagation::Origin::Establishes(crate::error::RetryAdvice::No.into())
    }
}

impl From<DPoPNotConfigured> for Error {
    #[track_caller]
    fn from(source: DPoPNotConfigured) -> Self {
        Self::from_cause(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn erased_no_dpop_dispatches() {
        let dpop: Arc<dyn AuthorizationServerDPoP> = Arc::new(NoDPoP);
        let uri = Uri::from_static("https://as.example/token");

        let proof = dpop.proof(&Method::POST, &uri, None).await.unwrap();
        assert!(proof.is_none());

        let _err = dpop
            .proof(&Method::POST, &uri, Some("jkt"))
            .await
            .unwrap_err();

        let resource = dpop.to_resource_server_dpop();
        let _err = resource
            .proof(&Method::GET, &uri, &SecretString::new("token"), "jkt")
            .await
            .unwrap_err();
    }
}
