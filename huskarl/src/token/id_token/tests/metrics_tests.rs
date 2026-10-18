use std::sync::Mutex;

use super::*;

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<(::metrics::Key, u64)>>>);

struct Counter {
    recorder: Recorder,
    key: ::metrics::Key,
}

impl ::metrics::CounterFn for Counter {
    fn increment(&self, value: u64) {
        self.recorder
            .0
            .lock()
            .unwrap()
            .push((self.key.clone(), value));
    }

    fn absolute(&self, _: u64) {
        panic!("validation counters must increment");
    }
}

impl ::metrics::Recorder for Recorder {
    fn describe_counter(
        &self,
        _: ::metrics::KeyName,
        _: Option<::metrics::Unit>,
        _: ::metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _: ::metrics::KeyName,
        _: Option<::metrics::Unit>,
        _: ::metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _: ::metrics::KeyName,
        _: Option<::metrics::Unit>,
        _: ::metrics::SharedString,
    ) {
    }
    fn register_counter(
        &self,
        key: &::metrics::Key,
        _: &::metrics::Metadata<'_>,
    ) -> ::metrics::Counter {
        if key.name() != "huskarl.id_token.validate" {
            return ::metrics::Counter::noop();
        }
        ::metrics::Counter::from_arc(Arc::new(Counter {
            recorder: self.clone(),
            key: key.clone(),
        }))
    }
    fn register_gauge(&self, _: &::metrics::Key, _: &::metrics::Metadata<'_>) -> ::metrics::Gauge {
        ::metrics::Gauge::noop()
    }
    fn register_histogram(
        &self,
        _: &::metrics::Key,
        _: &::metrics::Metadata<'_>,
    ) -> ::metrics::Histogram {
        ::metrics::Histogram::noop()
    }
}

#[test]
fn counts_final_validation_results_once_without_claim_values() {
    let recorder = Recorder::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let (signer, verifier) = signer_and_verifier().await;
            let validator = validator(verifier, None, None);
            let token = mint_standard(&signer, IdTokenClaims::default()).await;
            let original = validator.validate(&token, None).await.unwrap();
            assert!(
                validator
                    .validate(&token, Some("secret-nonce"))
                    .await
                    .is_err()
            );
            assert!(
                validator
                    .validate(&IdToken::from("secret-malformed-token"), None)
                    .await
                    .is_err()
            );
            let wrong_audience = mint(
                &signer,
                ISS,
                vec!["secret-wrong-audience".into()],
                Some(SUB),
                IdTokenClaims::default(),
            )
            .await;
            assert!(validator.validate(&wrong_audience, None).await.is_err());
            validator.validate_refresh(&token, &original).await.unwrap();
            let changed_subject = mint(
                &signer,
                ISS,
                vec![AUD.into()],
                Some("secret-changed-subject"),
                IdTokenClaims::default(),
            )
            .await;
            assert!(
                validator
                    .validate_refresh(&changed_subject, &original)
                    .await
                    .is_err()
            );
            assert!(
                validator
                    .validate_refresh(&wrong_audience, &original)
                    .await
                    .is_err()
            );
        });
    });

    let events = recorder.0.lock().unwrap();
    let expected = [
        "success",
        "nonce_mismatch",
        "malformed_jwt",
        "audience_mismatch",
        "success",
        "refresh_claim_mismatch",
        "audience_mismatch",
    ];
    assert_eq!(events.len(), expected.len(), "{events:?}");
    for ((key, value), outcome) in events.iter().zip(expected) {
        assert_eq!(*value, 1);
        let labels: std::collections::BTreeMap<_, _> = key
            .labels()
            .map(|label| (label.key(), label.value()))
            .collect();
        let expected_labels = std::collections::BTreeMap::from([("outcome", outcome)]);
        assert_eq!(labels, expected_labels);
    }
}

#[test]
fn signature_failure_outcomes_match_jws_metric_labels() {
    use crate::core::crypto::verifier::VerifyError;

    for (source, expected) in [
        (VerifyError::AmbiguousKeyMatch, "ambiguous_key"),
        (
            VerifyError::Other {
                source: crate::core::Error::new(
                    crate::core::RetryAdvice::RETRY,
                    "secret backend details",
                ),
            },
            "error",
        ),
    ] {
        let error = IdTokenValidationError::Jwt {
            source: JwtValidationError::Signature { source },
        };
        assert_eq!(error.outcome().as_str(), expected);
    }
}
