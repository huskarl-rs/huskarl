//! Assertions on observed client behavior. Never used to drive protocol actions.
use serde_json::Value;

use crate::{
    api::TestResult,
    client_error::{ClientError, Rejection, TokenRejection},
    report::ModuleEvidence,
};

enum Expected {
    Discovery,
    DiscoveryRejection,
    Success { attempts: usize },
    AuthorizationRejection(Rejection),
    UserInfoRejection,
}

fn expected(name: &str) -> Result<Expected, String> {
    use Expected::*;
    use TokenRejection::*;
    let oidc = name.strip_prefix("oidcc-client-test");
    if let Some(suffix) = oidc {
        return Ok(match suffix {
            "-discovery-openid-config" | "-discovery-jwks-uri-keys" => Discovery,
            "-discovery-issuer-mismatch" => DiscoveryRejection,
            ""
            | "-client-secret-basic"
            | "-idtoken-sig-rs256"
            | "-kid-absent-single-jwks"
            | "-scope-userinfo-claims"
            | "-signing-key-rotation-just-before-signing" => Success { attempts: 1 },
            "-signing-key-rotation" => Success { attempts: 2 },
            "-userinfo-invalid-sub" => UserInfoRejection,
            "-invalid-iss" => AuthorizationRejection(Rejection::IdToken(ClaimMismatch("iss"))),
            "-invalid-aud" => AuthorizationRejection(Rejection::IdToken(ClaimMismatch("aud"))),
            "-missing-sub" => AuthorizationRejection(Rejection::IdToken(MissingClaim("sub"))),
            "-missing-iat" => AuthorizationRejection(Rejection::IdToken(MissingClaim("iat"))),
            "-nonce-invalid" => AuthorizationRejection(Rejection::IdToken(Nonce)),
            "-idtoken-sig-none" => AuthorizationRejection(Rejection::IdToken(Unsigned)),
            "-invalid-sig-rs256" => AuthorizationRejection(Rejection::IdToken(Signature)),
            "-kid-absent-multiple-jwks" => AuthorizationRejection(Rejection::IdToken(AmbiguousKey)),
            _ => return Err(format!("no client expectation registered for {name}")),
        });
    }
    if let Some(suffix) = name.strip_prefix("fapi2-security-profile-final-client-test-") {
        return Ok(match suffix {
            "discovery-issuer-mismatch" => DiscoveryRejection,
            "happy-path"
            | "happy-path-no-dpop-nonce"
            | "valid-aud-as-array"
            | "rs-dpop-auth-scheme-case-insensitivity"
            | "token-type-case-insensitivity"
            | "token-endpoint-response-without-expires_in" => Success { attempts: 1 },
            "invalid-iss" => AuthorizationRejection(Rejection::IdToken(ClaimMismatch("iss"))),
            "invalid-aud" => AuthorizationRejection(Rejection::IdToken(ClaimMismatch("aud"))),
            "invalid-secondary-aud" => {
                AuthorizationRejection(Rejection::IdToken(UntrustedAudience))
            }
            "invalid-null-alg" => AuthorizationRejection(Rejection::IdToken(Unsigned)),
            "invalid-alternate-alg" => AuthorizationRejection(Rejection::IdToken(Algorithm)),
            "invalid-expired-exp" => AuthorizationRejection(Rejection::IdToken(Expired)),
            "invalid-missing-exp" => {
                AuthorizationRejection(Rejection::IdToken(MissingClaim("exp")))
            }
            "invalid-missing-aud" => {
                // The validator represents an absent audience as an empty list.
                AuthorizationRejection(Rejection::IdToken(ClaimMismatch("aud")))
            }
            "invalid-missing-iss" => {
                AuthorizationRejection(Rejection::IdToken(MissingClaim("iss")))
            }
            "invalid-nonce" | "invalid-missing-nonce" => {
                AuthorizationRejection(Rejection::IdToken(Nonce))
            }
            "invalid-authorization-response-iss" => {
                AuthorizationRejection(Rejection::CallbackIssuer)
            }
            "remove-authorization-response-iss" => {
                AuthorizationRejection(Rejection::MissingCallbackIssuer)
            }
            "ensure-authorization-response-with-invalid-state-fails" => {
                AuthorizationRejection(Rejection::CallbackState)
            }
            "ensure-authorization-response-with-invalid-missing-state-fails" => {
                AuthorizationRejection(Rejection::MissingCallbackState)
            }
            "ensure-jarm-without-iss-fails" => {
                AuthorizationRejection(Rejection::Jarm(MissingClaim("iss")))
            }
            "ensure-jarm-with-invalid-iss-fails" => {
                AuthorizationRejection(Rejection::Jarm(ClaimMismatch("iss")))
            }
            "ensure-jarm-without-aud-fails" => {
                AuthorizationRejection(Rejection::Jarm(ClaimMismatch("aud")))
            }
            "ensure-jarm-with-invalid-aud-fails" => {
                AuthorizationRejection(Rejection::Jarm(ClaimMismatch("aud")))
            }
            "ensure-jarm-without-exp-fails" => {
                AuthorizationRejection(Rejection::Jarm(MissingClaim("exp")))
            }
            "ensure-jarm-with-expired-exp-fails" => {
                AuthorizationRejection(Rejection::Jarm(Expired))
            }
            "ensure-jarm-with-invalid-sig-fails" => {
                AuthorizationRejection(Rejection::Jarm(Signature))
            }
            "ensure-jarm-signature-is-not-none" => {
                AuthorizationRejection(Rejection::Jarm(Unsigned))
            }
            _ => return Err(format!("no client expectation registered for {name}")),
        });
    }
    Err(format!("no client expectation registered for {name}"))
}

fn success<T>(result: Option<&Result<T, ClientError>>, operation: &str) -> Result<(), String> {
    match result {
        Some(Ok(_)) => Ok(()),
        Some(Err(error)) => Err(format!("{operation} must succeed: {error}")),
        None => Err(format!("{operation} was not performed")),
    }
}

fn rejection<T>(
    result: Option<&Result<T, ClientError>>,
    expected: &Rejection,
) -> Result<(), String> {
    match result {
        Some(Err(error)) if error.rejection.as_ref() == Some(expected) => Ok(()),
        Some(Err(error)) => Err(format!(
            "expected {expected:?}, got {:?}: {error}",
            error.rejection
        )),
        Some(Ok(_)) => Err(format!(
            "expected {expected:?}, but client accepted the response"
        )),
        None => Err(format!(
            "expected {expected:?}, but operation was not performed"
        )),
    }
}

fn resources(
    values: &std::collections::BTreeMap<String, Result<Option<u16>, ClientError>>,
    fapi: bool,
    oidc: bool,
) -> Result<(), String> {
    if oidc {
        success(values.get("userinfo"), "UserInfo validation")?;
    }
    if fapi {
        success(values.get("accounts"), "accounts request")?;
        if !matches!(values.get("accounts"), Some(Ok(Some(200..=299)))) {
            return Err("accounts request did not return a successful HTTP status".into());
        }
    }
    for (name, result) in values {
        success(Some(result), name)?;
        if matches!(result, Ok(Some(status)) if !(200..300).contains(status)) {
            return Err(format!("{name} returned a non-success HTTP status"));
        }
    }
    Ok(())
}

pub fn check(evidence: &ModuleEvidence, variant: &Value) -> Result<(), String> {
    let expected = expected(&evidence.name)?;
    // A module skipped before any client action provides no behavioral evidence.
    // Keep SKIPPED distinct in the suite counts, but do not demand nonexistent actions.
    if evidence
        .suite
        .as_ref()
        .is_some_and(|info| info.result == Some(TestResult::Skipped))
        && evidence.preparation.is_none()
        && evidence.registration.is_none()
        && evidence.token_exchange.is_none()
        && evidence.authorization.is_none()
        && evidence.authorization_attempts.is_empty()
        && evidence.resources.is_empty()
    {
        return Ok(());
    }
    let fapi = evidence.name.starts_with("fapi2-");
    let client_credentials = variant["fapi_profile"] == "fapi_client_credentials_grant";
    let oidc = !client_credentials && (!fapi || variant["fapi_client_type"] != "plain_oauth");
    if matches!(expected, Expected::DiscoveryRejection) {
        rejection(evidence.preparation.as_ref(), &Rejection::DiscoveryIssuer)?;
        if evidence.authorization.is_some()
            || evidence.registration.is_some()
            || evidence.token_exchange.is_some()
            || !evidence.resources.is_empty()
            || !evidence.authorization_attempts.is_empty()
        {
            return Err("client continued after rejecting discovery".into());
        }
        return Ok(());
    }
    success(evidence.preparation.as_ref(), "preparation")?;
    if variant["client_registration"] == "dynamic_client"
        && !matches!(expected, Expected::Discovery)
    {
        success(evidence.registration.as_ref(), "dynamic registration")?;
    }
    if client_credentials {
        if evidence.authorization.is_some()
            || !evidence.authorization_attempts.is_empty()
            || evidence.resources.contains_key("userinfo")
        {
            return Err("client credentials performed authorization or UserInfo actions".into());
        }
        if !matches!(expected, Expected::Success { .. }) {
            return Err("unsupported client-credentials expectation".into());
        }
        success(
            evidence.token_exchange.as_ref(),
            "client-credentials exchange",
        )?;
        return resources(&evidence.resources, true, false);
    }
    match expected {
        Expected::Discovery => {
            if evidence.authorization.is_some()
                || evidence.registration.is_some()
                || evidence.token_exchange.is_some()
                || !evidence.resources.is_empty()
                || !evidence.authorization_attempts.is_empty()
            {
                return Err(
                    "discovery-only scenario performed authorization/resource actions".into(),
                );
            }
        }
        Expected::AuthorizationRejection(reason) => {
            rejection(evidence.authorization.as_ref(), &reason)?;
            if !evidence.resources.is_empty() {
                return Err("client used resources after rejected authorization".into());
            }
            for attempt in &evidence.authorization_attempts {
                rejection(Some(&attempt.authorization), &reason)?;
                if !attempt.resources.is_empty() {
                    return Err("client used resources after rejected authorization attempt".into());
                }
            }
        }
        Expected::UserInfoRejection => {
            success(evidence.authorization.as_ref(), "authorization")?;
            rejection(
                evidence.resources.get("userinfo"),
                &Rejection::UserInfoSubject,
            )?;
            if evidence.resources.len() != 1 {
                return Err("client continued after rejected UserInfo".into());
            }
        }
        Expected::Success { attempts } => {
            success(evidence.authorization.as_ref(), "authorization")?;
            resources(&evidence.resources, fapi, oidc)?;
            if !fapi && evidence.authorization_attempts.len() != attempts {
                return Err(format!(
                    "expected {attempts} authorization attempts, got {}",
                    evidence.authorization_attempts.len()
                ));
            }
            for attempt in &evidence.authorization_attempts {
                success(Some(&attempt.authorization), "authorization attempt")?;
                resources(&attempt.resources, fapi, oidc)?;
            }
        }
        Expected::DiscoveryRejection => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{
        api::{ModuleInfo, ModuleStatus},
        report::AuthorizationAttempt,
    };

    fn positive() -> ModuleEvidence {
        ModuleEvidence {
            name: "fapi2-security-profile-final-client-test-happy-path".into(),
            preparation: Some(Ok(())),
            authorization: Some(Ok(())),
            resources: [
                ("accounts".into(), Ok(Some(200))),
                ("userinfo".into(), Ok(None)),
            ]
            .into(),
            suite: Some(ModuleInfo {
                id: "test".into(),
                status: ModuleStatus::Finished,
                result: Some(TestResult::Passed),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn suite_pass_cannot_hide_missing_actions_errors_or_bad_status() {
        let variant = json!({"fapi_client_type": "oidc"});
        assert!(check(&positive(), &variant).is_ok());
        for status in [401, 500] {
            let mut evidence = positive();
            evidence
                .resources
                .insert("accounts".into(), Ok(Some(status)));
            assert!(check(&evidence, &variant).is_err());
        }
        let mut evidence = positive();
        evidence.resources.remove("userinfo");
        assert!(check(&evidence, &variant).is_err());
        evidence = positive();
        evidence.authorization = Some(Err("connection reset".into()));
        assert!(check(&evidence, &variant).is_err());
        evidence = positive();
        evidence.preparation = None;
        assert!(check(&evidence, &variant).is_err());
    }

    #[test]
    fn negative_requires_the_right_reason_and_no_resource_use() {
        let mut evidence = positive();
        evidence.name = "fapi2-security-profile-final-client-test-invalid-iss".into();
        evidence.resources.clear();
        for reason in [
            None,
            Some(Rejection::IdToken(TokenRejection::Expired)),
            Some(Rejection::Jarm(TokenRejection::ClaimMismatch("iss"))),
        ] {
            evidence.authorization = Some(Err(ClientError {
                message: "rejected".into(),
                rejection: reason,
            }));
            assert!(check(&evidence, &json!({})).is_err());
        }
        evidence.authorization = Some(Err(ClientError {
            message: "rejected issuer".into(),
            rejection: Some(Rejection::IdToken(TokenRejection::ClaimMismatch("iss"))),
        }));
        assert!(check(&evidence, &json!({})).is_ok());
        evidence.resources.insert("accounts".into(), Ok(Some(200)));
        assert!(check(&evidence, &json!({})).is_err());
    }

    #[test]
    fn rotation_checks_every_attempt_and_requires_two() {
        let mut evidence = positive();
        evidence.name = "oidcc-client-test-signing-key-rotation".into();
        evidence.resources.remove("accounts");
        evidence.authorization_attempts.push(AuthorizationAttempt {
            authorization: Ok(()),
            resources: evidence.resources.clone(),
        });
        assert!(check(&evidence, &json!({})).is_err());
        evidence.authorization_attempts.push(AuthorizationAttempt {
            authorization: Ok(()),
            resources: evidence.resources.clone(),
        });
        assert!(check(&evidence, &json!({})).is_ok());
        evidence.authorization_attempts[0].authorization = Err("earlier failure".into());
        assert!(check(&evidence, &json!({})).is_err());
    }

    #[test]
    fn unknown_modules_fail_and_oauth_does_not_require_userinfo() {
        let mut evidence = positive();
        evidence.resources.remove("userinfo");
        assert!(check(&evidence, &json!({"fapi_client_type": "plain_oauth"})).is_ok());
        evidence.name = "new-upstream-module".into();
        assert!(check(&evidence, &json!({})).is_err());
    }

    #[test]
    fn dynamic_registration_requires_success_before_authorization() {
        let mut evidence = positive();
        evidence.name = "oidcc-client-test".into();
        evidence.resources.remove("accounts");
        evidence.authorization_attempts.push(AuthorizationAttempt {
            authorization: Ok(()),
            resources: evidence.resources.clone(),
        });
        let variant = json!({"client_registration": "dynamic_client"});
        assert!(check(&evidence, &variant).is_err());
        evidence.registration = Some(Err("registration failed".into()));
        assert!(check(&evidence, &variant).is_err());
        evidence.registration = Some(Ok(()));
        assert!(check(&evidence, &variant).is_ok());
    }

    #[test]
    fn client_credentials_requires_exchange_and_resource_without_browser_or_userinfo() {
        let mut evidence = positive();
        evidence.authorization = None;
        evidence.resources.remove("userinfo");
        let variant = json!({"fapi_profile": "fapi_client_credentials_grant"});
        assert!(check(&evidence, &variant).is_err());
        evidence.token_exchange = Some(Err("token endpoint failed".into()));
        assert!(check(&evidence, &variant).is_err());
        evidence.token_exchange = Some(Ok(()));
        assert!(check(&evidence, &variant).is_ok());
        evidence.authorization = Some(Ok(()));
        assert!(check(&evidence, &variant).is_err());
        evidence.authorization = None;
        evidence.resources.insert("userinfo".into(), Ok(None));
        assert!(check(&evidence, &variant).is_err());
        evidence.resources.remove("userinfo");
        evidence.resources.insert("accounts".into(), Ok(Some(401)));
        assert!(check(&evidence, &variant).is_err());
    }

    #[test]
    fn discovery_rejection_requires_discovery_failure_and_stops_the_flow() {
        let mut evidence = ModuleEvidence {
            name: "oidcc-client-test-discovery-issuer-mismatch".into(),
            preparation: Some(Err(ClientError {
                message: "issuer mismatch".into(),
                rejection: Some(Rejection::DiscoveryIssuer),
            })),
            ..Default::default()
        };
        assert!(check(&evidence, &json!({})).is_ok());
        evidence.authorization = Some(Ok(()));
        assert!(check(&evidence, &json!({})).is_err());
        evidence.authorization = None;
        evidence.preparation = Some(Err("discovery timed out".into()));
        assert!(check(&evidence, &json!({})).is_err());
    }

    #[test]
    fn userinfo_negative_requires_successful_authorization_and_subject_rejection() {
        let mut evidence = positive();
        evidence.name = "oidcc-client-test-userinfo-invalid-sub".into();
        evidence.resources.clear();
        evidence.resources.insert(
            "userinfo".into(),
            Err(ClientError {
                message: "subject mismatch".into(),
                rejection: Some(Rejection::UserInfoSubject),
            }),
        );
        assert!(check(&evidence, &json!({})).is_ok());
        evidence.authorization = Some(Err("unrelated failure".into()));
        assert!(check(&evidence, &json!({})).is_err());
        evidence.authorization = Some(Ok(()));
        evidence.resources.insert("userinfo".into(), Ok(None));
        assert!(check(&evidence, &json!({})).is_err());
    }

    #[test]
    fn skipped_module_cannot_hide_observed_client_failure() {
        let mut evidence = positive();
        evidence.suite.as_mut().unwrap().result = Some(TestResult::Skipped);
        evidence.authorization = Some(Err("unexpected error".into()));
        assert!(check(&evidence, &json!({})).is_err());
        evidence.preparation = None;
        evidence.authorization = None;
        evidence.resources.clear();
        assert!(check(&evidence, &json!({})).is_ok());
    }
}
