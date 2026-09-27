use http::Uri;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;
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
        EndpointUrl, Error, RetryAdvice,
        client_auth::AuthenticationContext,
        dpop::AuthorizationServerDPoP,
        jwt::validator::{JwtValidator, ValidatedJwt},
        platform::{Duration, SystemTime},
        secrets::SecretString,
    },
    grant::{
        authorization_code::{
            AuthorizationCodeGrantParameters,
            error::{
                CompleteError, ConstructingAuthorizationUrlSnafu, CreatingRequestObjectSnafu,
                EncodingParametersSnafu, FlowError, IdTokenIssuerNotConfiguredSnafu,
                IdTokenVerifierNotConfiguredSnafu, IssuerMismatchSnafu,
                JarmIssuerNotConfiguredSnafu, JarmMissingParameterSnafu, JarmValidationSnafu,
                JarmVerifierNotConfiguredSnafu, MissingIdTokenSnafu, MissingIssuerSnafu,
                MissingJarmResponseSnafu, PushedAuthorizationRequestSnafu, StateMismatchSnafu,
                UnexpectedJarmResponseSnafu, ValidatingIdTokenSnafu,
            },
            grant::AuthorizationCodeGrant,
            par,
            pkce::Pkce,
            types::{
                AuthorizationPayload, AuthorizationPayloadWithClientId, AuthorizationResponse,
                CallbackPayload, CompleteInput, CompleteOutput, PendingState, ResponseMode,
                StartInput, StartOutput,
            },
        },
        core::{OAuth2ExchangeGrant, TokenResponse, form::with_dpop_nonce_retry, join_space},
    },
    token::id_token::IdTokenValidator,
};

/// Constant-time `state` check — one layer of CSRF protection.
///
/// An absent one fails: RFC 6749 §4.1.2.1 requires `state` on any response to a
/// request that carried it, and forbids redirecting at all when it could not.
fn check_state(pending_state: &PendingState, callback_state: Option<&str>) -> Result<(), Error> {
    let matched = callback_state.is_some_and(|state| {
        pending_state
            .state
            .as_bytes()
            .ct_eq(state.as_bytes())
            .into()
    });

    if matched {
        Ok(())
    } else {
        Err(Error::from(StateMismatchSnafu.build()))
    }
}

impl AuthorizationCodeGrant {
    /// Completes the authorization code flow on `listener`, returning the token
    /// response and, for an OIDC flow, the validated ID token.
    ///
    /// Runs a minimal HTTP server on `listener` to receive the redirect callback
    /// at the redirect URI — handy for command-line tools. See [`complete`] for
    /// the ID-token semantics carried on [`CompleteOutput`].
    ///
    /// [`complete`]: Self::complete
    ///
    /// # Errors
    ///
    /// Returns a [`LoopbackError`] if the callback server fails, a callback URL
    /// cannot be parsed, the authorization server returns an error response, or
    /// the token (and ID token) exchange fails.
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
    ) -> Result<CompleteOutput, LoopbackError> {
        loopback::complete_on_loopback(
            listener,
            &pending_state.redirect_uri,
            renderer,
            async |complete_input| self.complete(pending_state, complete_input).await,
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
        // An OIDC flow must end in ID-token validation (OIDC Core 1.0
        // §3.1.3.3), so a grant that can never validate one fails here,
        // before the user is redirected to the authorization server.
        let is_oidc = self.oidc.unwrap_or_else(|| start_input.requests_openid());
        if is_oidc {
            if self.jws_verifier.is_none() {
                return Err(Error::new(
                    RetryAdvice::No,
                    super::error::OidcVerifierNotConfiguredSnafu.build(),
                ));
            }
            if self.issuer.is_none() {
                return Err(Error::new(
                    RetryAdvice::No,
                    super::error::OidcIssuerNotConfiguredSnafu.build(),
                ));
            }
        }

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

        let payload = build_authorization_payload(
            self,
            &start_input,
            pkce.as_ref(),
            dpop_jkt.clone(),
            is_oidc,
        );

        let request_object = self
            .request_object(payload.clone())
            .await
            .context(CreatingRequestObjectSnafu)?;

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
        let response_mode = payload.rest.response_mode;

        Ok(StartOutput {
            authorization_url,
            expires_at,
            pending_state: PendingState {
                redirect_uri: self.redirect_uri.clone(),
                pkce_verifier: pkce.map(|p| p.verifier),
                // The raw scope fact, not `is_oidc`: completion re-resolves
                // against the grant's `oidc` override.
                openid_requested: start_input.requests_openid(),
                state: start_input.state,
                nonce: nonce_sent.then_some(start_input.nonce),
                dpop_jkt,
                response_mode,
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
                // OIDC Core §6.1 requires these outside the request object too.
                // Copy the signed values so both representations agree.
                response_type: &'a str,
                #[serde(skip_serializing_if = "Option::is_none")]
                scope: Option<&'a str>,
            }
            add_payload_to_uri(
                &self.authorization_endpoint,
                JarRedirect {
                    client_id: &self.client_id,
                    request: request_jwt.expose_secret(),
                    response_type: payload.rest.response_type,
                    scope: payload.rest.scope.as_deref(),
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
        })
        .context(PushedAuthorizationRequestSnafu)?;

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
    /// response and, for an OIDC flow, the validated ID token.
    ///
    /// [`CompleteOutput::id_token`] is `Some` — validated — whenever the flow
    /// is OIDC (see the `oidc` builder setting); `None` means the flow was not
    /// OIDC, or the server narrowed `openid` out of the granted scope.
    ///
    /// # Errors
    ///
    /// Returns an error if the callback was an OAuth error response
    /// (the server's [`verdict`](crate::core::Error::verdict)), the token request
    /// failed, a check failed against the callback parameters, a received ID
    /// token could not be validated, or an OIDC flow's token response carried
    /// no ID token.
    pub async fn complete(
        &self,
        pending_state: &PendingState,
        complete_input: CompleteInput,
    ) -> Result<CompleteOutput, Error> {
        let result = self.complete_inner(pending_state, complete_input).await;
        self.observe_completion(&result);
        result
    }

    /// Records the completion's metrics outcome.
    #[allow(unused_variables)]
    #[cfg_attr(not(feature = "metrics"), allow(clippy::unused_self))]
    fn observe_completion(&self, result: &Result<CompleteOutput, Error>) {
        #[cfg(feature = "metrics")]
        {
            use crate::grant::GrantOutcome;
            let outcome = match result {
                Ok(_) => GrantOutcome::Success,
                Err(err) => super::error::completion_outcome(err),
            };
            let mut labels = self.metric_labels.clone();
            labels.push(::metrics::Label::new("outcome", outcome.as_str()));
            ::metrics::counter!("huskarl.grant.complete", labels).increment(1);
        }
    }

    async fn complete_inner(
        &self,
        pending_state: &PendingState,
        complete_input: CompleteInput,
    ) -> Result<CompleteOutput, Error> {
        // Fold the callback into a single response shape (JARM verified, then
        // plain params) so every check below runs the same way on both.
        let response = self
            .normalize_callback(pending_state, complete_input.payload)
            .await?;

        // An error response surfaces here, not at parse time, so it is state-
        // checked too: an unsolicited one is CSRF, not a denied login.
        let (code, iss) = match response {
            AuthorizationResponse::Success { code, state, iss } => {
                check_state(pending_state, Some(&state))?;
                (code, iss)
            }
            AuthorizationResponse::Error {
                error,
                error_description,
                error_uri,
                state,
            } => {
                check_state(pending_state, state.as_deref())?;

                // Convert the wire fields into the verdict carried by `Error`.
                return Err(Error::from(CompleteError::OAuthError {
                    verdict: crate::core::OAuthError::new(error)
                        .with_description(error_description)
                        .with_uri(error_uri),
                }));
            }
        };

        // RFC 9207 - check issuer match.
        if self.authorization_response_iss_parameter_supported
            && let Some(config_issuer) = self.issuer.as_deref()
        {
            if let Some(issuer) = iss {
                // The issuer is public, not a secret, so a constant-time
                // comparison is not required here (unlike `state` above).
                if issuer.as_bytes() != config_issuer.as_bytes() {
                    return Err(Error::from(
                        IssuerMismatchSnafu {
                            original: config_issuer,
                            callback: issuer,
                        }
                        .build(),
                    ));
                }
            } else {
                // Server claimed to support RFC 9207 but no issuer received.
                return Err(Error::from(MissingIssuerSnafu.build()));
            }
        }

        // Reject a different session key before spending the authorization code.
        if pending_state.dpop_jkt.is_some()
            && self.dpop.get_current_thumbprint().await != pending_state.dpop_jkt
        {
            return Err(FlowError::DPoPKeyMismatch.into());
        }

        let token = self
            .exchange(AuthorizationCodeGrantParameters {
                dpop_jkt: pending_state.dpop_jkt.clone(),
                code,
                pkce_verifier: pending_state.pkce_verifier.clone(),
                resource: complete_input.resource,
            })
            .await?;

        self.finalize_id_token(pending_state, token).await
    }

    /// Validates a returned ID token and enforces the OIDC requirement for one.
    async fn finalize_id_token(
        &self,
        pending_state: &PendingState,
        token: TokenResponse,
    ) -> Result<CompleteOutput, Error> {
        if let Some(id_token) = &token.id_token() {
            let verifier = self
                .jws_verifier
                .as_ref()
                .ok_or_else(|| Error::from(IdTokenVerifierNotConfiguredSnafu.build()))?
                .clone();
            let issuer = self
                .issuer
                .as_deref()
                .ok_or_else(|| Error::from(IdTokenIssuerNotConfiguredSnafu.build()))?
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
                .context(ValidatingIdTokenSnafu)?;

            Ok(CompleteOutput {
                token_response: token,
                id_token: Some(verified_token),
            })
        } else {
            // OIDC Core 1.0 §3.1.3.3: the token response must carry an ID
            // token when `openid` is granted. Granted scope defaults to the
            // requested scope when the response omits it (RFC 6749 §5.1), so
            // an absent `scope` is not a narrowing signal; a forced
            // `oidc(true)` grant skips the narrowing excuse entirely.
            let expected = self.oidc.unwrap_or(pending_state.openid_requested);
            let narrowed = self.oidc.is_none()
                && token
                    .raw_token_response()
                    .scope
                    .as_deref()
                    .is_some_and(|granted| granted.split(' ').all(|s| s != "openid"));
            if expected && !narrowed {
                return Err(Error::from(MissingIdTokenSnafu.build()));
            }
            Ok(CompleteOutput {
                token_response: token,
                id_token: None,
            })
        }
    }

    /// Folds a callback payload into the single [`AuthorizationResponse`] shape
    /// every later check runs on — the state check and error surfacing then
    /// have no third shape to consider.
    ///
    /// Verifies a JARM JWT before folding it in, and enforces the shape
    /// recorded at start in both directions: a plain callback when JARM was
    /// requested is a signature-stripping downgrade; an unrequested JARM JWT
    /// is unverifiable.
    async fn normalize_callback(
        &self,
        pending_state: &PendingState,
        payload: CallbackPayload,
    ) -> Result<AuthorizationResponse, Error> {
        let jarm_expected = pending_state
            .response_mode
            .is_some_and(ResponseMode::is_jwt_secured);

        match (payload, jarm_expected) {
            (CallbackPayload::Jarm { response }, true) => self.validate_jarm(&response).await,
            (CallbackPayload::Plain(response), false) => Ok(response),
            (CallbackPayload::Jarm { .. }, false) => {
                Err(Error::from(UnexpectedJarmResponseSnafu.build()))
            }
            (CallbackPayload::Plain(_), true) => Err(Error::from(MissingJarmResponseSnafu.build())),
        }
    }

    /// Verifies a JARM response JWT (JARM §2.4: signature, `iss`, `aud`,
    /// `exp`) and folds its claims into an [`AuthorizationResponse`].
    async fn validate_jarm(&self, response: &str) -> Result<AuthorizationResponse, Error> {
        /// The authorization-response parameters as JWT claims (JARM §2.1).
        #[derive(Debug, Clone, Deserialize)]
        struct JarmClaims {
            code: Option<String>,
            state: Option<String>,
            error: Option<String>,
            error_description: Option<String>,
            error_uri: Option<String>,
        }

        let verifier = self
            .jws_verifier
            .clone()
            .ok_or_else(|| Error::from(JarmVerifierNotConfiguredSnafu.build()))?;
        let issuer = self
            .issuer
            .as_deref()
            .ok_or_else(|| Error::from(JarmIssuerNotConfiguredSnafu.build()))?;

        let validator = JwtValidator::builder()
            .verifier(verifier)
            .iss(issuer.to_owned())
            .aud(self.client_id.clone())
            .require_exp(true)
            .maybe_allowed_algorithms(self.allowed_authorization_signed_response_algs.clone())
            .build();

        let validated: ValidatedJwt<JarmClaims> = validator
            .validate(response)
            .await
            .context(JarmValidationSnafu)?;

        let claims = validated.claims;
        if let Some(error) = claims.error {
            return Ok(AuthorizationResponse::Error {
                error,
                error_description: claims.error_description,
                error_uri: claims.error_uri,
                state: claims.state,
            });
        }
        let param = |value: Option<String>, param: &'static str| {
            value.ok_or_else(|| Error::from(JarmMissingParameterSnafu { param }.build()))
        };
        Ok(AuthorizationResponse::Success {
            code: param(claims.code, "code")?,
            state: param(claims.state, "state")?,
            iss: validated.iss,
        })
    }
}

fn build_authorization_payload<'a>(
    grant: &'a AuthorizationCodeGrant,
    start_input: &'a StartInput,
    pkce: Option<&'a Pkce>,
    dpop_jkt: Option<String>,
    is_oidc: bool,
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
            // default it follows the flow's OIDC-ness: OIDC flows get it
            // (binding any returned ID token), pure-OAuth servers that
            // strictly reject unknown parameters do not. `send_oidc_nonce`
            // forces the wire parameter either way.
            nonce: grant
                .send_oidc_nonce
                .unwrap_or(is_oidc)
                .then_some(start_input.nonce.as_str()),
            response_mode: grant.response_mode,
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
    let query = crate::core::oauth_form::to_string(&payload).context(EncodingParametersSnafu)?;
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
    Ok(uri_string
        .parse::<Uri>()
        .context(ConstructingAuthorizationUrlSnafu)?)
}

#[cfg(test)]
mod tests;
