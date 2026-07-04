use std::sync::Arc;

use http::{Method, Uri};
use snafu::Snafu;

use crate::{
    dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
    error::{Error, ErrorKind},
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
                Err(Error::new(ErrorKind::DPoP, DPoPNotConfigured))
            } else {
                Ok(None)
            }
        })
    }

    fn to_resource_server_dpop(&self) -> Arc<dyn ResourceServerDPoP> {
        Arc::new(NoDPoP)
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
        Box::pin(async { Err(Error::new(ErrorKind::DPoP, DPoPNotConfigured)) })
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

        let err = dpop
            .proof(&Method::POST, &uri, Some("jkt"))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DPoP);

        let resource = dpop.to_resource_server_dpop();
        let err = resource
            .proof(&Method::GET, &uri, &SecretString::new("token"), "jkt")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DPoP);
    }
}
