use http::Uri;
use serde::Serialize;
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
        EndpointUrl, Error, ErrorKind,
        client_auth::AuthenticationContext,
        jwt::validator::ValidatedJwt,
        platform::{Duration, SystemTime},
        secrets::SecretString,
    },
    grant::{
        authorization_code::{
            AuthorizationCodeGrantParameters,
            error::{
                IdTokenIssuerNotConfiguredSnafu, IdTokenVerifierNotConfiguredSnafu,
                IssuerMismatchSnafu, MissingIssuerSnafu, StateMismatchSnafu,
            },
            grant::AuthorizationCodeGrant,
            par,
            pkce::Pkce,
            types::{
                AuthorizationPayload, AuthorizationPayloadWithClientId, CompleteInput,
                PendingState, StartInput, StartOutput,
            },
        },
        core::{OAuth2ExchangeGrant, TokenResponse, form::with_dpop_nonce_retry, join_space},
    },
    token::id_token::{IdTokenClaims, IdTokenValidator},
};

/// Wraps a completion-check failure as a protocol error.
fn complete_error(source: super::error::CompleteError) -> Error {
    Error::new(ErrorKind::Protocol, source)
}

impl AuthorizationCodeGrant {
    /// Completes the authorization code flow on `listener`, returning the token
    /// response.
    ///
    /// Runs a minimal HTTP server on `listener` to receive the redirect callback
    /// at the redirect URI — handy for command-line tools. To also recover the
    /// validated ID token, use
    /// [`complete_on_loopback_oidc`](Self::complete_on_loopback_oidc).
    ///
    /// # Errors
    ///
    /// Errors if a callback URL cannot be parsed, the HTTP exchange or callback
    /// handling fails, the token request fails, or a returned ID token fails
    /// validation (see [`complete_oidc`](Self::complete_oidc)).
    #[cfg(all(
        feature = "authorization-flow-loopback",
        any(
            not(target_family = "wasm"),
            all(target_arch = "wasm32", target_os = "wasi", target_env = "p2")
        )
    ))]
    pub async fn complete_on_loopback(
        &self,
        listener: &tokio::net::TcpListener,
        pending_state: &PendingState,
        renderer: Option<loopback::CallbackRenderer>,
    ) -> Result<TokenResponse, LoopbackError> {
        self.complete_on_loopback_oidc(listener, pending_state, renderer)
            .await
            .map(|v| v.0)
    }

    /// Completes the authorization code flow on `listener`, returning the token
    /// response together with the validated ID token when the flow was an OIDC
    /// flow.
    ///
    /// Like [`complete_on_loopback`](Self::complete_on_loopback), but also yields
    /// the validated ID token. Same minimal callback server and the same errors.
    ///
    /// # Errors
    ///
    /// Returns a [`LoopbackError`] if the callback server fails, the
    /// authorization server returns an error response, or the token (and ID
    /// token) exchange fails.
    #[cfg(all(
        feature = "authorization-flow-loopback",
        any(
            not(target_family = "wasm"),
            all(target_arch = "wasm32", target_os = "wasi", target_env = "p2")
        )
    ))]
    pub async fn complete_on_loopback_oidc(
        &self,
        listener: &tokio::net::TcpListener,
        pending_state: &PendingState,
        renderer: Option<loopback::CallbackRenderer>,
    ) -> Result<(TokenResponse, Option<ValidatedJwt<IdTokenClaims>>), LoopbackError> {
        loopback::complete_on_loopback_oidc(
            listener,
            &pending_state.redirect_uri,
            renderer,
            async |complete_input| self.complete_oidc(pending_state, complete_input).await,
        )
        .await
    }

    async fn request_object(
        &self,
        payload: AuthorizationPayloadWithClientId<'_>,
    ) -> Result<Option<SecretString>, Error> {
        self.jar
            .generate_request_object(
                self.issuer
                    .as_deref()
                    .unwrap_or(&self.authorization_endpoint.to_string()),
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
    pub async fn start(&self, start_input: StartInput) -> Result<StartOutput, Error> {
        let supports_method = |method: &str| {
            self.code_challenge_methods_supported
                .iter()
                .any(|m| m == method)
        };
        let pkce = if self.disable_pkce {
            None
        } else if supports_method("plain") && !supports_method("S256") {
            // The server explicitly advertises `plain` but not `S256`; honor
            // that rather than send a challenge it cannot verify.
            Some(Pkce::generate_plain_pair())
        } else {
            // PKCE with S256 is always applied otherwise (RFC 9700 §2.1.1),
            // even when the server metadata omits the optional
            // `code_challenge_methods_supported` field — servers ignore
            // unrecognized request parameters (RFC 6749 §3.1).
            Some(Pkce::generate_s256_pair())
        };

        let dpop_jkt = self.dpop.get_current_thumbprint().await;

        let payload =
            build_authorization_payload(self, &start_input, pkce.as_ref(), dpop_jkt.clone());

        let request_object = self
            .request_object(payload.clone())
            .await
            .map_err(|e| e.with_context("creating JAR request object"))?;

        let (authorization_url, expires_at) = if let Some(par_url) =
            &self.pushed_authorization_request_endpoint
            && (self.prefer_pushed_authorization_requests
                || self.require_pushed_authorization_requests)
        {
            self.deliver_via_par(&payload, request_object.as_ref(), par_url)
                .await?
        } else {
            self.deliver_direct(&payload, request_object.as_ref())?
        };

        // Persist the nonce exactly when the parameter went out: the
        // completion side skips the nonce check when none was sent.
        let nonce_sent = payload.rest.nonce.is_some();

        Ok(StartOutput {
            authorization_url,
            expires_at,
            pending_state: PendingState {
                redirect_uri: self.redirect_uri.clone(),
                pkce_verifier: pkce.map(|p| p.verifier),
                state: start_input.state,
                nonce: nonce_sent.then_some(start_input.nonce),
                dpop_jkt,
            },
        })
    }

    fn deliver_direct(
        &self,
        payload: &AuthorizationPayloadWithClientId<'_>,
        request_object: Option<&SecretString>,
    ) -> Result<(Uri, Option<SystemTime>), Error> {
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

    async fn deliver_via_par(
        &self,
        payload: &AuthorizationPayloadWithClientId<'_>,
        request_object: Option<&SecretString>,
        par_url: &EndpointUrl,
    ) -> Result<(Uri, Option<SystemTime>), Error> {
        // RFC 9126 §2: `client_id` is REQUIRED in the PAR body in both forms.
        let par_body = match request_object {
            Some(jwt) => par::ParBody::Jar {
                client_id: &self.client_id,
                request: jwt.expose_secret(),
            },
            None => par::ParBody::Expanded(Box::new(payload.clone())),
        };

        let dpop_jkt = payload.rest.dpop_jkt.as_deref();

        let par_response = with_dpop_nonce_retry!({
            let mut auth_params = self
                .client_auth
                .authentication_context(
                    AuthenticationContext::builder()
                        .client_id(&self.client_id)
                        .target_endpoint(par_url)
                        .maybe_issuer(self.issuer.as_deref())
                        .token_endpoint(&self.token_endpoint)
                        .maybe_allowed_methods(
                            self.token_endpoint_auth_methods_supported.as_deref(),
                        )
                        .build(),
                )
                .await?;

            // RFC 9126 §2 requires `client_id` in the PAR body and `ParBody`
            // already carries it — drop the copy `client_secret_post` adds so it
            // isn't sent twice.
            if let Some(form) = auth_params.form_params.as_mut() {
                form.retain(|(name, _)| *name != "client_id");
            }

            par::make_par_call(
                self.http_client.as_ref(),
                par_url,
                auth_params,
                &par_body,
                self.dpop.as_ref(),
                dpop_jkt,
            )
            .await
            .map_err(|e| e.with_context("making PAR request"))
        })?;

        let push_payload = par::AuthorizationPushPayload {
            client_id: &self.client_id,
            request_uri: &par_response.request_uri,
        };

        // Resolve the relative `expires_in` to an absolute instant here, at
        // receipt — the only moment the anchor is known.
        let expires_at = SystemTime::now()
            .checked_add(Duration::from_secs(par_response.expires_in))
            .unwrap_or_else(SystemTime::now);

        Ok((
            add_payload_to_uri(&self.authorization_endpoint, push_payload)?,
            Some(expires_at),
        ))
    }

    /// Attempts to complete the authorization code flow, returning the token
    /// response.
    ///
    /// To also recover the validated ID token, use
    /// [`complete_oidc`](Self::complete_oidc).
    ///
    /// # Errors
    ///
    /// Returns an error if the token request fails, a callback parameter check
    /// fails, or a returned ID token fails validation (see
    /// [`complete_oidc`](Self::complete_oidc) for the ID-token semantics).
    pub async fn complete(
        &self,
        pending_state: &PendingState,
        complete_input: CompleteInput,
    ) -> Result<TokenResponse, Error> {
        self.complete_oidc(pending_state, complete_input)
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
    pub async fn complete_oidc(
        &self,
        pending_state: &PendingState,
        complete_input: CompleteInput,
    ) -> Result<(TokenResponse, Option<ValidatedJwt<IdTokenClaims>>), Error> {
        // Required state check (one layer of CSRF protection).
        if pending_state
            .state
            .as_bytes()
            .ct_ne(complete_input.state.as_bytes())
            .into()
        {
            return Err(complete_error(StateMismatchSnafu.build()));
        }

        // RFC 9207 - check issuer match.
        if self.authorization_response_iss_parameter_supported
            && let Some(config_issuer) = self.issuer.as_deref()
        {
            if let Some(issuer) = complete_input.iss {
                // The issuer is public, not a secret, so a constant-time
                // comparison is not required here (unlike `state` above).
                if issuer.as_bytes() != config_issuer.as_bytes() {
                    return Err(complete_error(
                        IssuerMismatchSnafu {
                            original: config_issuer,
                            callback: issuer,
                        }
                        .build(),
                    ));
                }
            } else {
                // Server claimed to support RFC 9207 but no issuer received.
                return Err(complete_error(MissingIssuerSnafu.build()));
            }
        }

        let token = self
            .exchange(AuthorizationCodeGrantParameters {
                dpop_jkt: pending_state.dpop_jkt.clone(),
                code: complete_input.code,
                pkce_verifier: pending_state.pkce_verifier.clone(),
                resource: complete_input.resource,
            })
            .await?;

        if let Some(id_token) = &token.id_token() {
            let verifier = self
                .jws_verifier
                .as_ref()
                .ok_or_else(|| complete_error(IdTokenVerifierNotConfiguredSnafu.build()))?
                .clone();
            let issuer = self
                .issuer
                .as_deref()
                .ok_or_else(|| complete_error(IdTokenIssuerNotConfiguredSnafu.build()))?
                .to_owned();

            let validator = IdTokenValidator::builder()
                .verifier(verifier)
                .issuer(issuer)
                .audience(self.client_id.clone())
                .maybe_allowed_algorithms(self.allowed_id_token_signed_response_algs.clone())
                .build();

            let verified_token = validator
                .validate(id_token, pending_state.nonce.as_deref())
                .await
                .map_err(|e| {
                    Error::new(ErrorKind::Protocol, e).with_context("validating ID token")
                })?;

            Ok((token, Some(verified_token)))
        } else {
            Ok((token, None))
        }
    }
}

fn build_authorization_payload<'a>(
    grant: &'a AuthorizationCodeGrant,
    start_input: &'a StartInput,
    pkce: Option<&'a Pkce>,
    dpop_jkt: Option<String>,
) -> AuthorizationPayloadWithClientId<'a> {
    AuthorizationPayloadWithClientId {
        client_id: &grant.client_id,
        rest: AuthorizationPayload {
            response_type: "code",
            redirect_uri: &grant.redirect_uri,
            scope: join_space(start_input.scope.as_deref()),
            state: &start_input.state,
            code_challenge: pkce.map(|p| p.challenge.as_ref()),
            code_challenge_method: pkce.map(|p| p.method),
            dpop_jkt,
            // `nonce` is an OIDC parameter (OIDC Core 1.0 §3.1.2.1), so by
            // default it is gated on the `openid` scope: OIDC flows get it (binding
            // any returned ID token), pure-OAuth servers that strictly reject
            // unknown parameters do not. `send_oidc_nonce` forces either way.
            nonce: {
                let is_oidc = start_input
                    .scope
                    .as_deref()
                    .is_some_and(|s| s.iter().any(|scope| scope == "openid"));
                grant
                    .send_oidc_nonce
                    .unwrap_or(is_oidc)
                    .then_some(start_input.nonce.as_str())
            },
            display: start_input.display.as_ref(),
            prompt: start_input.prompt.as_ref(),
            max_age: start_input.max_age.map(|d| d.as_secs()),
            ui_locales: join_space(start_input.ui_locales.as_deref()),
            id_token_hint: start_input.id_token_hint.as_ref(),
            login_hint: start_input.login_hint.as_deref(),
            acr_values: join_space(start_input.acr_values.as_deref()),
            resource: start_input.resource.as_deref(),
            authorization_details: start_input.authorization_details.as_deref(),
        },
    }
}

fn add_payload_to_uri<T: Serialize>(endpoint: &EndpointUrl, payload: T) -> Result<Uri, Error> {
    let query = crate::core::oauth_form::to_string(&payload).map_err(|e| {
        Error::new(ErrorKind::Config, e).with_context("encoding authorization request parameters")
    })?;
    let separator = if endpoint.as_uri().query().is_some() {
        '&'
    } else {
        '?'
    };
    let uri_string = format!("{endpoint}{separator}{query}");
    // The form encoder only emits valid query characters, so the result is
    // well-formed — but `http::Uri` caps the total URI length at u16::MAX,
    // which large parameters (notably `id_token_hint`, an entire JWT) can
    // exceed. PAR is the spec-blessed delivery for oversized requests.
    uri_string.parse().map_err(|e: http::uri::InvalidUri| {
        Error::new(ErrorKind::Config, e).with_context(
            "constructing authorization URL (oversized requests should be delivered via PAR)",
        )
    })
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{
        core::{
            client_auth::NoAuth,
            http::{HttpClient, HttpResponse, Idempotency},
            platform::MaybeSendBoxFuture,
            server_metadata::AuthorizationServerMetadata,
        },
        grant::authorization_code::types::StartInput,
    };

    /// `start()` with direct delivery performs no HTTP; this client asserts that.
    struct NoHttp;

    impl HttpClient for NoHttp {
        fn execute(
            &self,
            _request: http::Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            unreachable!("start() with direct delivery must not perform HTTP")
        }
    }

    type Grant = AuthorizationCodeGrant;

    async fn start_url(grant: &Grant) -> String {
        grant
            .start(StartInput::scope(bon::vec!["openid"]))
            .await
            .unwrap()
            .authorization_url
            .to_string()
    }

    /// Serves one canned PAR response, for exercising the PAR delivery path.
    struct ParHttp;

    impl HttpClient for ParHttp {
        fn execute(
            &self,
            _request: http::Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            Box::pin(async {
                Ok(HttpResponse {
                    status: http::StatusCode::CREATED,
                    headers: http::HeaderMap::new(),
                    body: Bytes::from_static(
                        br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}"#,
                    ),
                })
            })
        }
    }

    #[tokio::test]
    async fn par_start_resolves_expiry_to_an_absolute_instant() {
        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(ParHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .pushed_authorization_request_endpoint("https://as.example.com/par".parse().unwrap())
            .prefer_pushed_authorization_requests(true)
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        let before = SystemTime::now();
        let output = grant
            .start(StartInput::scope(bon::vec!["openid"]))
            .await
            .unwrap();
        let expires_at = output.expires_at.expect("PAR delivery sets an expiry");

        // The RFC 9126 `expires_in` (90s) is anchored at receipt.
        let lower = before + Duration::from_secs(90);
        let upper = SystemTime::now() + Duration::from_secs(90);
        assert!(
            expires_at >= lower && expires_at <= upper,
            "expected within [{lower:?}, {upper:?}], got {expires_at:?}"
        );
    }

    #[tokio::test]
    async fn direct_start_has_no_expiry() {
        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        let output = grant
            .start(StartInput::scope(bon::vec!["openid"]))
            .await
            .unwrap();
        assert_eq!(output.expires_at, None);
    }

    #[tokio::test]
    async fn default_builder_uses_s256() {
        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        let url = start_url(&grant).await;
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        assert!(url.contains("code_challenge="), "{url}");
    }

    /// Requiring PAR without a PAR endpoint must fail at build time: the only
    /// way to proceed would be silently downgrading to a plain authorization
    /// request (RFC 9126 §5).
    #[tokio::test]
    async fn required_par_without_endpoint_fails_the_build() {
        let result = AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .require_pushed_authorization_requests(true)
            .build()
            .await;

        let err = result
            .err()
            .expect("build must fail without a PAR endpoint");
        assert_eq!(err.kind(), crate::core::ErrorKind::Config, "got {err:?}");
    }

    /// Control: the same requirement with an endpoint configured builds fine.
    #[tokio::test]
    async fn required_par_with_endpoint_builds() {
        AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .pushed_authorization_request_endpoint("https://as.example.com/par".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .require_pushed_authorization_requests(true)
            .build()
            .await
            .unwrap();
    }

    /// The persisted nonce must track whether the parameter was actually
    /// sent: completion skips the check when it wasn't, so an ID token
    /// legitimately issued without a nonce claim validates.
    #[tokio::test]
    async fn nonce_persisted_only_when_sent() {
        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        let openid = grant
            .start(StartInput::scope(bon::vec!["openid"]))
            .await
            .unwrap();
        assert!(
            openid.pending_state.nonce.is_some(),
            "openid scope sends the nonce, so it must be persisted"
        );

        let plain = grant
            .start(StartInput::scope(bon::vec!["profile"]))
            .await
            .unwrap();
        assert!(
            plain.pending_state.nonce.is_none(),
            "no openid scope: nonce not sent, so none persisted for completion"
        );
    }

    #[tokio::test]
    async fn authorization_details_carried_as_a_single_json_value() {
        use crate::core::AuthorizationDetail;

        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        let start_input = StartInput::builder()
            .scope(bon::vec!["openid"])
            .authorization_details(vec![
                AuthorizationDetail::builder("payment_initiation")
                    .with("actions", serde_json::json!(["initiate"]))
                    .build(),
            ])
            .build();

        let url = grant
            .start(start_input)
            .await
            .unwrap()
            .authorization_url
            .to_string();

        // RFC 9396 §3: one `authorization_details` parameter carrying URL-encoded
        // JSON (`%5B%7B` is `[{`), not repeated keys like a scalar list.
        assert_eq!(url.matches("authorization_details=").count(), 1, "{url}");
        assert!(url.contains("authorization_details=%5B%7B"), "{url}");
    }

    #[test]
    fn start_input_scope_is_optional() {
        // RFC 6749 §3.1.1 / RFC 9396 §3: a request may omit scope and carry only
        // authorization_details.
        let start_input = StartInput::builder()
            .authorization_details(vec![
                crate::core::AuthorizationDetail::builder("payment_initiation").build(),
            ])
            .build();
        assert!(start_input.scope.is_none());
        assert!(start_input.authorization_details.is_some());
    }

    #[tokio::test]
    async fn metadata_without_code_challenge_methods_still_uses_s256() {
        // RFC 8414 makes `code_challenge_methods_supported` optional even for
        // servers that support PKCE; omission must not silently disable it.
        let metadata: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as.example.com",
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "https://as.example.com/token",
            "response_types_supported": ["code"],
        }))
        .unwrap();

        let grant: Grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
            .unwrap()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        let url = start_url(&grant).await;
        assert!(url.contains("code_challenge_method=S256"), "{url}");
    }

    #[tokio::test]
    async fn id_token_algs_default_from_metadata_dropping_none() {
        // OIDC Discovery `id_token_signing_alg_values_supported` seeds the
        // allowlist so the ID-token `alg` is pinned to what the issuer
        // advertises; the insecure `none` value is dropped.
        let metadata: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as.example.com",
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "https://as.example.com/token",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "none"],
        }))
        .unwrap();

        let grant: Grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
            .unwrap()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        let algs = grant
            .allowed_id_token_signed_response_algs
            .expect("allowlist defaulted from metadata");
        assert!(algs.contains("RS256"), "{algs:?}");
        assert!(algs.contains("ES256"), "{algs:?}");
        assert!(
            !algs.contains("none"),
            "insecure `none` must be dropped: {algs:?}"
        );
    }

    #[tokio::test]
    async fn id_token_algs_unset_when_metadata_omits_them() {
        let metadata: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as.example.com",
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "https://as.example.com/token",
            "response_types_supported": ["code"],
        }))
        .unwrap();

        let grant: Grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
            .unwrap()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        assert!(grant.allowed_id_token_signed_response_algs.is_none());
    }

    #[tokio::test]
    async fn explicit_id_token_algs_via_plain_builder() {
        // The plain `builder()` path takes an explicit allowlist (no metadata
        // seeding), pinning exactly the configured algorithms.
        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .allowed_id_token_signed_response_algs(
                ["PS256".to_string()]
                    .into_iter()
                    .collect::<std::collections::HashSet<_>>(),
            )
            .build()
            .await
            .unwrap();

        let algs = grant
            .allowed_id_token_signed_response_algs
            .expect("explicit allowlist");
        assert_eq!(algs.len(), 1, "{algs:?}");
        assert!(algs.contains("PS256"), "{algs:?}");
    }

    #[tokio::test]
    async fn plain_only_metadata_uses_plain() {
        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .code_challenge_methods_supported(vec!["plain".to_string()])
            .build()
            .await
            .unwrap();

        let url = start_url(&grant).await;
        assert!(url.contains("code_challenge_method=plain"), "{url}");
    }

    #[tokio::test]
    async fn oversized_authorization_url_errors_instead_of_panicking() {
        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        // `http::Uri` caps the total URI length at u16::MAX; a large
        // `id_token_hint` (an entire JWT in a query parameter) must surface
        // as an error rather than a panic.
        let result = grant
            .start(
                StartInput::builder()
                    .scope(bon::vec!["openid"])
                    .id_token_hint(crate::token::IdToken::from("a".repeat(70 * 1024)))
                    .build(),
            )
            .await;
        assert!(
            matches!(result, Err(ref err) if err.kind() == ErrorKind::Config),
            "oversized authorization URL should fail with a Config error"
        );
    }

    #[tokio::test]
    async fn disable_pkce_omits_challenge() {
        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .http_client(NoHttp)
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .disable_pkce(true)
            .build()
            .await
            .unwrap();

        let url = start_url(&grant).await;
        assert!(!url.contains("code_challenge"), "{url}");
    }
}
