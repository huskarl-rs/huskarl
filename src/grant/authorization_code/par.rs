use serde::{Deserialize, Serialize};

use crate::{
    EndpointUrl,
    client_auth::AuthenticationParams,
    dpop::AuthorizationServerDPoP,
    grant::{
        authorization_code::types::AuthorizationPayload,
        core::form::{OAuth2FormError, OAuth2FormRequest},
    },
    http::{HttpClient, HttpResponse},
};

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(super) enum ParBody<'a> {
    Expanded(AuthorizationPayload<'a>),
    Jar { request: &'a str },
}

#[derive(Debug, Serialize)]
pub(super) struct AuthorizationPushPayload<'a> {
    pub client_id: &'a str,
    pub request_uri: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct AuthorizationPushResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

pub(super) async fn make_par_call<C: HttpClient, D: AuthorizationServerDPoP>(
    http_client: &C,
    par_url: &EndpointUrl,
    auth_params: AuthenticationParams<'_>,
    payload: &ParBody<'_>,
    dpop: &D,
) -> Result<
    AuthorizationPushResponse,
    OAuth2FormError<C::Error, <C::Response as HttpResponse>::Error, D::Error>,
> {
    OAuth2FormRequest::builder()
        .form(payload)
        .auth_params(auth_params)
        .uri(par_url.as_uri())
        .dpop(dpop)
        .build()
        .execute(http_client)
        .await
}
