//! Client information response (RFC 7591 §3.2.1).

use serde::{Deserialize, Deserializer, de};

use super::metadata::ClientMetadata;
use crate::core::{
    platform::{Duration, SystemTime},
    secrets::SecretString,
};

/// When an issued client secret expires (RFC 7591 §3.2.1).
///
/// The wire encodes this as one optional number: an absent field means no secret
/// was issued, `0` means it never expires, and any other value is the expiry
/// instant — one variant each.
// A distinct enum, not Option<SystemTime>, so `0` (never-expires) isn't
// conflated with the Unix epoch.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum ClientSecretExpiry {
    /// No client secret was issued, so no expiry applies.
    #[default]
    NoSecret,
    /// A client secret was issued and does not expire.
    NeverExpires,
    /// A client secret was issued and expires at the given time.
    At(SystemTime),
}

impl<'de> Deserialize<'de> for ClientSecretExpiry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Option::<i64>::deserialize(deserializer)? {
            None => Ok(Self::NoSecret),
            Some(0) => Ok(Self::NeverExpires),
            Some(secs) if secs > 0 => {
                let secs = u64::try_from(secs).map_err(de::Error::custom)?;
                let at = SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(secs))
                    .ok_or_else(|| {
                        de::Error::custom("client_secret_expires_at overflows SystemTime")
                    })?;
                Ok(Self::At(at))
            }
            Some(_) => Err(de::Error::custom(
                "client_secret_expires_at cannot be negative",
            )),
        }
    }
}

/// The successful result of a client registration (RFC 7591 §3.2.1).
///
/// Carries the issued `client_id` and, for confidential clients, a
/// `client_secret`. The metadata the server actually registered — which may
/// differ from what was requested — is flattened into [`metadata`](Self::metadata),
/// and any members the server returned beyond the recognized set land in
/// [`ClientMetadata::extra`].
///
/// The RFC 7592 registration-management fields
/// ([`registration_access_token`](Self::registration_access_token) and
/// [`registration_client_uri`](Self::registration_client_uri)) are captured
/// when the server provides them, for later read/update/delete management.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct ClientInformationResponse {
    /// The issued OAuth 2.0 client identifier.
    pub client_id: String,

    /// The issued client secret, for confidential clients.
    pub client_secret: Option<SecretString>,

    /// Time at which the `client_id` was issued.
    #[serde(default, with = "crate::core::serde_utils::time::option_unix_secs")]
    pub client_id_issued_at: Option<SystemTime>,

    /// When the issued client secret expires.
    #[serde(default)]
    pub client_secret_expires_at: ClientSecretExpiry,

    /// The registration access token for managing this client (RFC 7592).
    pub registration_access_token: Option<SecretString>,

    /// The client configuration endpoint for managing this client (RFC 7592).
    pub registration_client_uri: Option<String>,

    /// The metadata the server registered for the client.
    #[serde(flatten)]
    pub metadata: ClientMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: serde_json::Value) -> ClientInformationResponse {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn absent_expiry_means_no_secret() {
        let resp = parse(serde_json::json!({ "client_id": "abc" }));
        assert_eq!(resp.client_secret_expires_at, ClientSecretExpiry::NoSecret);
        assert!(resp.client_secret.is_none());
    }

    #[test]
    fn zero_expiry_means_never_expires() {
        let resp = parse(serde_json::json!({
            "client_id": "abc",
            "client_secret": "shh",
            "client_secret_expires_at": 0,
        }));
        assert_eq!(
            resp.client_secret_expires_at,
            ClientSecretExpiry::NeverExpires
        );
        assert_eq!(resp.client_secret.as_ref().unwrap().expose_secret(), "shh");
    }

    #[test]
    fn positive_expiry_is_an_instant() {
        let resp = parse(serde_json::json!({
            "client_id": "abc",
            "client_secret": "shh",
            "client_secret_expires_at": 1_700_000_000,
            "client_id_issued_at": 1_600_000_000,
        }));
        assert_eq!(
            resp.client_secret_expires_at,
            ClientSecretExpiry::At(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        );
        assert_eq!(
            resp.client_id_issued_at,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000))
        );
    }

    #[test]
    fn negative_expiry_is_rejected() {
        let err = serde_json::from_value::<ClientInformationResponse>(serde_json::json!({
            "client_id": "abc",
            "client_secret_expires_at": -1,
        }))
        .unwrap_err();
        assert!(err.to_string().contains("negative"), "{err}");
    }

    #[test]
    fn registered_metadata_and_management_fields_are_captured() {
        let resp = parse(serde_json::json!({
            "client_id": "abc",
            "client_name": "My App",
            "redirect_uris": ["https://app.example/cb"],
            "registration_access_token": "reg-token",
            "registration_client_uri": "https://as.example/register/abc",
            "some_extension": 42,
        }));

        assert_eq!(resp.metadata.client_name.as_deref(), Some("My App"));
        assert_eq!(resp.metadata.redirect_uris, vec!["https://app.example/cb"]);
        assert_eq!(
            resp.registration_access_token
                .as_ref()
                .unwrap()
                .expose_secret(),
            "reg-token"
        );
        assert_eq!(
            resp.registration_client_uri.as_deref(),
            Some("https://as.example/register/abc")
        );
        // Unrecognized members land in the flattened metadata's extras.
        assert_eq!(resp.metadata.extra.get("some_extension").unwrap(), 42);
    }
}
