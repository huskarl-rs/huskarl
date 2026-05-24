use http::Uri;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use subtle::ConstantTimeEq;

#[cfg(all(
    feature = "authorization-flow-loopback",
    any(
        not(target_family = "wasm"),
        all(target_arch = "wasm32", target_os = "wasi", target_env = "p2")
    )
))]
use crate::grant::authorization_code::{LoopbackError, loopback};
use crate::{
    core::{
        EndpointUrl, client_auth::ClientAuthentication, dpop::AuthorizationServerDPoP,
        http::HttpClient, jwt::validator::ValidatedJwt, platform::MaybeSendSync,
        secrets::SecretString,
    },
    grant::{
        authorization_code::{
            AuthorizationCodeGrantParameters,
            error::{
                ClientAuthSnafu, CompleteError, EncodeUrlEncodedSnafu, GrantSnafu,
                IdTokenIssuerNotConfiguredSnafu, IdTokenValidationSnafu,
                IdTokenVerifierNotConfiguredSnafu, IssuerMismatchSnafu, JarSnafu,
                MissingIssuerSnafu, ParRequestSnafu, StartError, StateMismatchSnafu,
            },
            grant::AuthorizationCodeGrant,
            jar::Jar,
            par,
            pkce::Pkce,
            types::{
                AuthorizationPayload, AuthorizationPayloadWithClientId, CompleteInput,
                PendingState, StartInput, StartOutput,
            },
        },
        core::{ExchangeError, OAuth2ExchangeGrant, TokenResponse, form::with_dpop_nonce_retry},
    },
    token::id_token::{IdTokenClaims, IdTokenValidator},
};

impl<
    Auth: ClientAuthentication + 'static,
    D: AuthorizationServerDPoP + Clone + 'static,
    J: Jar + 'static,
    IdClaims: Clone + for<'de> Deserialize<'de> + MaybeSendSync + 'static,
> AuthorizationCodeGrant<Auth, D, J, IdClaims>
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
    /// callback, or errors requesting a token, or if a supplied ID token could not be validated.
    ///
    /// Note that if an ID token is returned by the authorization server, this indicates that an
    /// OIDC flow was requested in the authorization request, and the ID token will be validated.
    #[cfg(all(
        feature = "authorization-flow-loopback",
        any(
            not(target_family = "wasm"),
            all(target_arch = "wasm32", target_os = "wasi", target_env = "p2")
        )
    ))]
    pub async fn complete_on_loopback<C: HttpClient>(
        &self,
        http_client: &C,
        listener: &tokio::net::TcpListener,
        pending_state: &PendingState,
        renderer: Option<loopback::CallbackRenderer>,
    ) -> Result<TokenResponse, LoopbackError<CompleteError<ExchangeError<C, Self>>>> {
        self.complete_on_loopback_oidc(http_client, listener, pending_state, renderer)
            .await
            .map(|v| v.0)
    }

    /// Completes the authorization code flow on the provided listener, possibly returning a token response and an ID token.
    ///
    /// A lightweight HTTP server is implemented on the listener, which is capable of handling
    /// the authorization code callback at the redirect URI. This may be useful in various use
    /// cases, especially that of command-line utilities.
    ///
    /// # Errors
    ///
    /// Errors if there are issues with parsing callback URLs, HTTP read errors, errors handling the
    /// callback, or errors requesting a token, or if the ID token cannot be validated.
    #[cfg(all(
        feature = "authorization-flow-loopback",
        any(
            not(target_family = "wasm"),
            all(target_arch = "wasm32", target_os = "wasi", target_env = "p2")
        )
    ))]
    pub async fn complete_on_loopback_oidc<C: HttpClient>(
        &self,
        http_client: &C,
        listener: &tokio::net::TcpListener,
        pending_state: &PendingState,
        renderer: Option<loopback::CallbackRenderer>,
    ) -> Result<
        (TokenResponse, Option<ValidatedJwt<IdTokenClaims<IdClaims>>>),
        LoopbackError<CompleteError<ExchangeError<C, Self>>>,
    > {
        loopback::complete_on_loopback_oidc(
            listener,
            &pending_state.redirect_uri,
            renderer,
            async |complete_input| {
                self.complete_oidc(http_client, pending_state, complete_input)
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
                    .as_deref()
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
    ) -> Result<StartOutput, StartError<Auth::Error, C::Error, C::ResponseError, D::Error, J::Error>>
    {
        let pkce = if self
            .code_challenge_methods_supported
            .iter()
            .any(|m| m == "S256")
        {
            Some(Pkce::generate_s256_pair())
        } else if self
            .code_challenge_methods_supported
            .iter()
            .any(|m| m == "plain")
        {
            Some(Pkce::generate_plain_pair())
        } else {
            None
        };

        let dpop_jkt = self.dpop.get_current_thumbprint();

        let payload =
            build_authorization_payload(self, &start_input, pkce.as_ref(), dpop_jkt.clone());

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
                pkce_verifier: pkce.map(|p| p.verifier),
                state: start_input.state,
                nonce: start_input.nonce,
                dpop_jkt,
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
                    client_id: &self.client_id,
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
        StartError<Auth::Error, C::Error, C::ResponseError, D::Error, J::Error>,
    > {
        let effective_par_url = if http_client.uses_mtls() {
            self.mtls_pushed_authorization_request_endpoint
                .as_ref()
                .unwrap_or(par_url)
        } else {
            par_url
        };

        let par_body = match request_object {
            Some(jwt) => par::ParBody::Jar {
                request: jwt.expose_secret(),
            },
            None => par::ParBody::Expanded(Box::new(payload.clone())),
        };

        let dpop_jkt = self.dpop.get_current_thumbprint();

        let par_response = with_dpop_nonce_retry!({
            let auth_params = self
                .client_auth
                .authentication_params(
                    &self.client_id,
                    self.issuer.as_deref(),
                    effective_par_url.as_uri(),
                    self.token_endpoint_auth_methods_supported.as_deref(),
                )
                .await
                .context(ClientAuthSnafu)?;

            par::make_par_call(
                http_client,
                effective_par_url,
                auth_params,
                &par_body,
                &self.dpop,
                dpop_jkt.as_deref(),
            )
            .await
            .context(ParRequestSnafu)
        })?;

        let push_payload = par::AuthorizationPushPayload {
            client_id: &self.client_id,
            request_uri: &par_response.request_uri,
        };

        Ok((
            add_payload_to_uri(&self.authorization_endpoint, push_payload)
                .context(EncodeUrlEncodedSnafu)?,
            Some(par_response.expires_in),
        ))
    }

    /// Attempts to complete the authorization code flow, returning the token response.
    ///
    /// # Errors
    ///
    /// Returns an error if one is returned when sending a message to the token endpoint,
    /// a check failed against the callback parameters, or if a received ID token could not be validated.
    ///
    /// Note that if an ID token is returned by the authorization server, this indicates that an
    /// OIDC flow was requested in the authorization request, and the ID token will be validated.
    pub async fn complete<C: HttpClient>(
        &self,
        http_client: &C,
        pending_state: &PendingState,
        complete_input: CompleteInput,
    ) -> Result<TokenResponse, CompleteError<ExchangeError<C, Self>>> {
        self.complete_oidc(http_client, pending_state, complete_input)
            .await
            .map(|(token_response, _)| token_response)
    }

    /// Attempts to complete the authorization code flow, returning both the token response and the validated ID token.
    ///
    /// # Errors
    ///
    /// Returns an error if one is returned when sending a message to the token endpoint,
    /// a check failed against the callback parameters, or if a received ID token could not be validated.
    ///
    /// Note that if an ID token is returned by the authorization server, this indicates that an
    /// OIDC flow was requested in the authorization request, and the ID token will be validated.
    pub async fn complete_oidc<C: HttpClient>(
        &self,
        http_client: &C,
        pending_state: &PendingState,
        complete_input: CompleteInput,
    ) -> Result<
        (TokenResponse, Option<ValidatedJwt<IdTokenClaims<IdClaims>>>),
        CompleteError<ExchangeError<C, Self>>,
    > {
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
            && let Some(config_issuer) = self.issuer.as_deref()
        {
            if let Some(issuer) = complete_input.iss {
                if issuer.as_bytes() != config_issuer.as_bytes() {
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

        let token = self
            .exchange(
                http_client,
                AuthorizationCodeGrantParameters {
                    dpop_jkt: pending_state.dpop_jkt.clone(),
                    code: complete_input.code.clone(),
                    pkce_verifier: pending_state.pkce_verifier.clone(),
                    resource: complete_input.resource.clone(),
                },
            )
            .await
            .context(GrantSnafu)?;

        if let Some(id_token) = &token.id_token() {
            let verifier = self
                .jws_verifier
                .as_ref()
                .ok_or_else(|| IdTokenVerifierNotConfiguredSnafu.build())?
                .clone();
            let issuer = self
                .issuer
                .as_deref()
                .ok_or_else(|| IdTokenIssuerNotConfiguredSnafu.build())?
                .to_owned();

            let validator = IdTokenValidator::builder()
                .verifier(verifier)
                .issuer(issuer)
                .audience(self.client_id.clone())
                .maybe_allowed_algorithms(self.allowed_id_token_signed_response_algs.clone())
                .build();

            let verified_token = validator
                .validate(id_token, Some(pending_state.nonce.as_str()))
                .await
                .context(IdTokenValidationSnafu)?;

            Ok((token, Some(verified_token)))
        } else {
            Ok((token, None))
        }
    }
}

fn build_authorization_payload<
    'a,
    Auth: ClientAuthentication + 'static,
    DPoP: AuthorizationServerDPoP + 'static,
    J: Jar + 'static,
    IdClaims: Clone + for<'de> Deserialize<'de> + MaybeSendSync + 'static,
>(
    grant: &'a AuthorizationCodeGrant<Auth, DPoP, J, IdClaims>,
    start_input: &'a StartInput,
    pkce: Option<&'a Pkce>,
    dpop_jkt: Option<String>,
) -> AuthorizationPayloadWithClientId<'a> {
    AuthorizationPayloadWithClientId {
        client_id: &grant.client_id,
        rest: AuthorizationPayload {
            response_type: "code",
            redirect_uri: &grant.redirect_uri,
            scope: start_input.scopes.as_deref(),
            state: &start_input.state,
            code_challenge: pkce.map(|p| p.challenge.as_ref()),
            code_challenge_method: pkce.map(|p| p.method),
            dpop_jkt,
            nonce: &start_input.nonce,
            display: start_input.display.as_ref(),
            prompt: start_input.prompt.as_ref(),
            max_age: start_input.max_age.as_ref(),
            ui_locales: start_input.ui_locales.as_ref().map(|l| l.join(" ")),
            id_token_hint: start_input.id_token_hint.as_ref(),
            login_hint: start_input.login_hint.as_deref(),
            acr_values: start_input.acr_values.as_ref().map(|l| l.join(" ")),
            resource: start_input.resource.as_deref(),
        },
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
