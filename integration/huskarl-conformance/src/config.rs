//! Configuration shared by the management API and protocol clients.
use std::{path::PathBuf, time::Duration};

use crate::api::Error;

// Deliberately no Debug: this contains the management API credential.
pub struct Config {
    pub base_url: String,
    pub api_token: Option<String>,
    pub insecure_tls: bool,
    pub request_timeout: Duration,
    pub evidence_dir: PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let base_url =
            get("CONFORMANCE_SUITE_BASE").unwrap_or_else(|| crate::CONFORMANCE_SUITE_BASE.into());
        let url = reqwest::Url::parse(&base_url)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("CONFORMANCE_SUITE_BASE must be an HTTP(S) URL without credentials, query or fragment".into());
        }
        let insecure_tls = match get("CONFORMANCE_INSECURE_TLS").as_deref() {
            None | Some("false" | "0") => false,
            Some("true" | "1") => true,
            _ => return Err("CONFORMANCE_INSECURE_TLS must be true/false or 1/0".into()),
        };
        let seconds = get("CONFORMANCE_REQUEST_TIMEOUT_SECONDS")
            .unwrap_or_else(|| "30".into())
            .parse::<u64>()?;
        if seconds == 0 {
            return Err("request timeout must be positive".into());
        }
        let api_token = get("CONFORMANCE_API_TOKEN").filter(|s| !s.is_empty());
        if api_token.is_some() && url.scheme() != "https" {
            return Err("management API tokens require HTTPS".into());
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').into(),
            api_token,
            insecure_tls,
            request_timeout: Duration::from_secs(seconds),
            evidence_dir: get("CONFORMANCE_EVIDENCE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/conformance")
                }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secure_defaults_and_explicit_local_override() {
        let config = Config::from_lookup(|_| None).unwrap();
        assert!(!config.insecure_tls);
        assert!(config.api_token.is_none());
        let config =
            Config::from_lookup(|key| (key == "CONFORMANCE_INSECURE_TLS").then(|| "true".into()))
                .unwrap();
        assert!(config.insecure_tls);
    }
    #[test]
    fn rejects_invalid_or_unsafe_configuration() {
        for (key, value) in [
            ("CONFORMANCE_INSECURE_TLS", "yes"),
            ("CONFORMANCE_REQUEST_TIMEOUT_SECONDS", "0"),
            ("CONFORMANCE_SUITE_BASE", "https://user:secret@example.com"),
        ] {
            assert!(Config::from_lookup(|name| (name == key).then(|| value.into())).is_err());
        }
        assert!(
            Config::from_lookup(|key| match key {
                "CONFORMANCE_API_TOKEN" => Some("secret".into()),
                "CONFORMANCE_SUITE_BASE" => Some("http://example.com".into()),
                _ => None,
            })
            .is_err()
        );
    }
}
