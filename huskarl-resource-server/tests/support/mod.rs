use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use http::{HeaderMap, Method, Uri, header::AUTHORIZATION};
use huskarl_resource_server::{
    core::platform::MaybeSendBoxFuture,
    validator::{
        AccessTokenValidator, ValidatedRequest, ValidationResult,
        extract::TokenExtractError,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
    },
};

pub type RequestCheck =
    fn(&HeaderMap, &Method, &Uri, Option<&[u8]>) -> Result<(), TokenExtractError>;

pub struct Stub {
    pub claims: Option<&'static str>,
    pub calls: Arc<AtomicUsize>,
    pub metadata: ValidatorMetadata,
    pub check: RequestCheck,
}

impl Stub {
    pub fn new(claims: &'static str) -> Self {
        Self {
            claims: Some(claims),
            calls: Arc::new(AtomicUsize::new(0)),
            metadata: ValidatorMetadata::builder().build(),
            check: |_, _, _, _| Ok(()),
        }
    }
}

impl AccessTokenValidator for Stub {
    type Claims = &'static str;
    type Error = TokenExtractError;

    fn validate_request<'a>(
        &'a self,
        headers: &'a HeaderMap,
        method: &'a Method,
        uri: &'a Uri,
        cert: Option<&'a [u8]>,
    ) -> MaybeSendBoxFuture<'a, ValidationResult<Self::Claims, Self::Error>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ValidationResult {
                outcome: (self.check)(headers, method, uri, cert).map(|()| {
                    self.claims.map(|claims| ValidatedRequest {
                        iss: None,
                        sub: Some("owner".into()),
                        aud: vec![],
                        jti: None,
                        iat: None,
                        exp: None,
                        cnf: None,
                        claims,
                        introspection_jwt: None,
                    })
                }),
                dpop_nonce: Some("nonce".into()),
            }
        })
    }
}

impl ProvideValidatorMetadata for Stub {
    fn validator_metadata(&self, _: Option<&str>) -> ValidatorMetadata {
        self.metadata.clone()
    }
}

pub fn headers(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, value.parse().unwrap());
    headers
}

pub async fn validate<V: AccessTokenValidator>(
    validator: &V,
    headers: &HeaderMap,
) -> ValidationResult<V::Claims, V::Error> {
    validator
        .validate_request(headers, &Method::GET, &Uri::from_static("/"), None)
        .await
}
