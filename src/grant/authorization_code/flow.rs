use http::Uri;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use snafu::ResultExt;
use subtle::ConstantTimeEq;

use crate::{
    EndpointUrl,
    client_auth::ClientAuthentication,
    dpop::AuthorizationServerDPoP,
    grant::{
        authorization_code::{
            error::{
                ClientAuthSnafu, CompleteError, EncodeUrlEncodedSnafu, GrantSnafu,
                IssuerMismatchSnafu, JarSnafu, MissingIssuerSnafu, ParRequestSnafu, StartError,
                StateMismatchSnafu,
            },
            exchange::AuthorizationCodeGrantParameters,
            grant::AuthorizationCodeGrant,
            jar::Jar,
            par,
            pkce::Pkce,
            types::{
                AuthorizationPayload, AuthorizationPayloadWithClientId, CompleteInput,
                PendingState, StartInput, StartOutput,
            },
        },
        core::{OAuth2ExchangeGrant, OAuth2ExchangeGrantError, TokenResponse},
    },
    http::{HttpClient, HttpResponse},
};

#[cfg(feature = "authorization-flow-loopback")]
use crate::grant::authorization_code::LoopbackError;

impl<
    Auth: ClientAuthentication + 'static,
    D: AuthorizationServerDPoP + Clone + 'static,
    J: Jar + 'static,
> AuthorizationCodeGrant<Auth, D, J>
{
    /// Completes the authorization code flow on the provided listener, possibly returning a token response.
    ///
    /// A lightweight HTTP server is implemented on the listener, which is capable of handling
    /// the authorization code callback at the redirect URI. This may be useful in various use
    /// cases, especially that of command-line utilities.
    ///
    /// # Errors
    ///
    /// Errors if there are issues with parsing callback URLs, HTTP read errors, errors handling the
    /// callback, or errors requesting a token.
    #[cfg(feature = "authorization-flow-loopback")]
    pub async fn complete_on_loopback<C: HttpClient>(
        &self,
        http_client: &C,
        listener: &tokio::net::TcpListener,
        pending_state: &PendingState,
    ) -> Result<
        TokenResponse,
        LoopbackError<
            CompleteError<
                OAuth2ExchangeGrantError<
                    C::Error,
                    <C::Response as HttpResponse>::Error,
                    Auth::Error,
                    D::Error,
                >,
            >,
        >,
    > {
        use crate::grant::authorization_code::loopback;

        loopback::complete_on_loopback(
            listener,
            &pending_state.redirect_uri,
            async |complete_input| {
                self.complete(http_client, pending_state, complete_input)
                    .await
            },
        )
        .await
    }

    async fn request_object(
        &self,
        payload: AuthorizationPayloadWithClientId<'_>,
    ) -> Result<Option<SecretString>, J::Error> {
        self.jar
            .generate_request_object(
                self.issuer
                    .as_ref()
                    .unwrap_or(&self.authorization_endpoint.as_uri().to_string()),
                payload,
            )
            .await
    }

    /// Starts an authorization code flow.
    ///
    /// This generates the request for the authorization code flow (optionally a JAR request object). If
    /// PAR is configured and chosen for use, the information is provided to the PAR endpoint, and the
    /// resulting URL is returned as the one to which the user should be directed for authorization. If
    /// PAR is not used, then the configured authorization endpoint is returned, with appropriate query
    /// parameters for the request.
    ///
    /// # Errors
    ///
    /// May return an error if the configuration is invalid, or the PAR endpoint returns an error.
    pub async fn start<C: HttpClient>(
        &self,
        http_client: &C,
        start_input: StartInput,
    ) -> Result<
        StartOutput,
        StartError<Auth::Error, C::Error, <C::Response as HttpResponse>::Error, D::Error, J::Error>,
    > {
        let pkce = Pkce::generate_s256_pair();
        let payload = build_authorization_payload(self, &start_input, &pkce);

        let request_object = self
            .request_object(payload.clone())
            .await
            .context(JarSnafu)?;

        let (authorization_url, expires_in) = if let Some(par_url) =
            &self.pushed_authorization_request_endpoint
            && (self.prefer_pushed_authorization_requests
                || self.require_pushed_authorization_requests)
        {
            self.deliver_via_par(http_client, &payload.rest, request_object.as_ref(), par_url)
                .await?
        } else {
            self.deliver_direct(&payload, request_object.as_ref())
                .context(EncodeUrlEncodedSnafu)?
        };

        Ok(StartOutput {
            authorization_url,
            expires_in,
            pending_state: PendingState {
                redirect_uri: self.redirect_uri.clone(),
                pkce_verifier: Some(pkce.verifier),
                state: start_input.state,
            },
        })
    }

    fn deliver_direct(
        &self,
        payload: &AuthorizationPayloadWithClientId<'_>,
        request_object: Option<&SecretString>,
    ) -> Result<(Uri, Option<u64>), serde_html_form::ser::Error> {
        let uri = if let Some(request_jwt) = request_object {
            #[derive(Serialize)]
            struct JarRedirect<'a> {
                client_id: &'a str,
                request: &'a str,
            }
            add_payload_to_uri(
                &self.authorization_endpoint,
                JarRedirect {
                    client_id: self.client_id.as_ref(),
                    request: request_jwt.expose_secret(),
                },
            )?
        } else {
            add_payload_to_uri(&self.authorization_endpoint, payload)?
        };
        Ok((uri, None))
    }

    async fn deliver_via_par<C: HttpClient>(
        &self,
        http_client: &C,
        payload: &AuthorizationPayload<'_>,
        request_object: Option<&SecretString>,
        par_url: &EndpointUrl,
    ) -> Result<
        (Uri, Option<u64>),
        StartError<Auth::Error, C::Error, <C::Response as HttpResponse>::Error, D::Error, J::Error>,
    > {
        let auth_params = self
            .authentication_params()
            .await
            .context(ClientAuthSnafu)?;

        let par_body = match request_object {
            Some(jwt) => par::ParBody::Jar {
                request: jwt.expose_secret(),
            },
            None => par::ParBody::Expanded(payload.clone()),
        };

        let par_response =
            par::make_par_call(http_client, par_url, auth_params, &par_body, self.dpop())
                .await
                .context(ParRequestSnafu)?;

        let push_payload = par::AuthorizationPushPayload {
            client_id: self.client_id.as_ref(),
            request_uri: &par_response.request_uri,
        };

        Ok((
            add_payload_to_uri(&self.authorization_endpoint, push_payload)
                .context(EncodeUrlEncodedSnafu)?,
            Some(par_response.expires_in),
        ))
    }

    /// Attempts to complete the authorization code flow.
    ///
    /// # Errors
    ///
    /// Returns an error if one is returned when sending a message to the token endpoint,
    /// or if a check failed against the callback parameters.
    pub async fn complete<C: HttpClient>(
        &self,
        http_client: &C,
        pending_state: &PendingState,
        complete_input: CompleteInput,
    ) -> Result<
        TokenResponse,
        CompleteError<
            OAuth2ExchangeGrantError<
                C::Error,
                <C::Response as HttpResponse>::Error,
                Auth::Error,
                D::Error,
            >,
        >,
    > {
        // Request the token even in cases where checks fail. This removes the
        // ability of an attacker to abuse the unused code.
        let token_or_error = self
            .exchange(
                http_client,
                AuthorizationCodeGrantParameters {
                    code: complete_input.code.clone(),
                    pkce_verifier: pending_state.pkce_verifier.clone(),
                },
            )
            .await
            .context(GrantSnafu);

        // Required state check (one layer of CSRF protection).
        if pending_state
            .state
            .as_bytes()
            .ct_ne(complete_input.state.as_bytes())
            .into()
        {
            return StateMismatchSnafu {
                original: pending_state.state.clone(),
                callback: complete_input.state,
            }
            .fail();
        }

        // RFC 9207 - check issuer match.
        if self.authorization_response_iss_parameter_supported
            && let Some(config_issuer) = &self.issuer
        {
            if let Some(issuer) = complete_input.iss {
                if issuer.as_bytes().ct_ne(config_issuer.as_bytes()).into() {
                    return IssuerMismatchSnafu {
                        original: config_issuer,
                        callback: issuer,
                    }
                    .fail();
                }
            } else {
                // Server claimed to support RFC 9207 but no issuer received.
                return MissingIssuerSnafu.fail();
            }
        }

        token_or_error
    }
}

fn build_payload_with_external_auth<
    'a,
    Auth: ClientAuthentication + 'static,
    DPoP: AuthorizationServerDPoP + 'static,
    J: Jar + 'static,
>(
    grant: &'a AuthorizationCodeGrant<Auth, DPoP, J>,
    start_input: &'a StartInput,
    pkce: &'a Pkce,
) -> AuthorizationPayload<'a> {
    AuthorizationPayload {
        response_type: "code",
        redirect_uri: &grant.redirect_uri,
        scope: start_input.scopes.as_deref(),
        state: &start_input.state,
        code_challenge: &pkce.challenge,
        code_challenge_method: "S256",
        dpop_jkt: grant.dpop().jwk_thumbprint(),
    }
}

fn build_authorization_payload<
    'a,
    Auth: ClientAuthentication + 'static,
    DPoP: AuthorizationServerDPoP + 'static,
    J: Jar + 'static,
>(
    grant: &'a AuthorizationCodeGrant<Auth, DPoP, J>,
    start_input: &'a StartInput,
    pkce: &'a Pkce,
) -> AuthorizationPayloadWithClientId<'a> {
    AuthorizationPayloadWithClientId {
        client_id: grant.client_id.as_ref(),
        rest: build_payload_with_external_auth(grant, start_input, pkce),
    }
}

fn add_payload_to_uri<T: Serialize>(
    endpoint: &EndpointUrl,
    payload: T,
) -> Result<Uri, serde_html_form::ser::Error> {
    let query = serde_html_form::to_string(&payload)?;
    let separator = if endpoint.as_uri().query().is_some() {
        '&'
    } else {
        '?'
    };
    let uri_string = format!("{}{separator}{query}", endpoint.as_uri());
    // The base URI is already valid and we're only appending a query string
    // produced by serde_html_form, which only emits valid query characters.
    Ok(uri_string
        .parse()
        .expect("appending a query string to a valid URI should produce a valid URI"))
}
