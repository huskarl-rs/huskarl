//! Client metadata (RFC 7591 §2).

use std::collections::HashMap;

use bon::Builder;
use serde::{Deserialize, Serialize};

use crate::core::{jwk::PublicJwks, secrets::SecretString};

/// Client metadata values associated with a client at an authorization server
/// (RFC 7591 §2).
///
/// Used both as the input to a registration request (the values the client
/// *requests*) and, flattened into [`ClientInformationResponse`], as the values
/// the server actually *registered*. Every field is optional: omitted fields
/// are left off the wire so the server applies its own defaults. The server MAY
/// substitute or reject requested values, so always consult the response.
///
/// Beyond the RFC 7591 §2 base parameters, the `OpenID` Connect Dynamic Client
/// Registration 1.0 §2 extension parameters are also typed. Any other extension
/// parameter round-trips through [`extra`](Self::extra).
///
/// [`ClientInformationResponse`]: super::ClientInformationResponse
#[derive(Clone, Debug, Default, Serialize, Deserialize, Builder)]
#[builder(on(String, into))]
#[non_exhaustive]
pub struct ClientMetadata {
    /// Redirection URIs to register for the client's redirect-based flows.
    /// Matched by exact string at the authorization server, so register each
    /// exactly as the client will send it.
    // Plain strings, not EndpointUrl: EndpointUrl normalizes (and rejects
    // native-app schemes, RFC 8252), which would break the exact-string match.
    // Same reason the authorization code grant uses `redirect_uri: String`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    pub redirect_uris: Vec<String>,

    /// Requested client authentication method for the token endpoint
    /// (e.g. `none`, `client_secret_post`, `client_secret_basic`).
    ///
    /// If omitted, the server default is `client_secret_basic`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,

    /// OAuth 2.0 grant type strings the client will use at the token endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    pub grant_types: Vec<String>,

    /// OAuth 2.0 response type strings the client will use at the authorization
    /// endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    pub response_types: Vec<String>,

    /// Human-readable name of the client, presented to the end-user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// URL of a web page with information about the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,

    /// URL referencing a logo for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    /// Space-separated list of scope values the client can request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Ways to contact people responsible for the client, typically email
    /// addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    pub contacts: Vec<String>,

    /// URL pointing to a human-readable terms of service document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,

    /// URL pointing to a human-readable privacy policy document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,

    /// URL referencing the client's JWK Set document.
    ///
    /// Per RFC 7591 §2, MUST NOT be present together with [`jwks`](Self::jwks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// The client's public JWK Set, inline (RFC 7591 §2).
    ///
    /// The builder accepts anything `Into<PublicJwks>` — including a
    /// [`Jwks`](crate::core::jwk::Jwks), whose private material is stripped, so
    /// only public keys reach the wire. MUST NOT be present together with
    /// [`jwks_uri`](Self::jwks_uri).
    // Deserialized via Jwks (PublicJwks isn't Deserialize), then reduced to its
    // public keys, so private/symmetric keys a server echoes can't enter the field.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "jwks_serde::deserialize"
    )]
    #[builder(into)]
    pub jwks: Option<PublicJwks>,

    /// A unique identifier for the client software, stable across instances.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,

    /// A version identifier for the client software.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,

    /// A software statement: a signed JWT asserting client metadata (RFC 7591
    /// §2.3), supplied pre-built. Serialized as the raw JWT.
    // SecretString, not String: the statement is bearer-presentable (no
    // proof-of-possession), so a leak lets a holder register as that software.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub software_statement: Option<SecretString>,

    /// Kind of client application — `web` (the default) or `native`
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,

    /// URL of a JSON file with the client's `redirect_uris`, providing the host
    /// the server uses when calculating `pairwise` `sub` values (`OpenID`
    /// Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,

    /// Requested subject identifier type — `pairwise` or `public`
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,

    /// JWS `alg` the client requests for signing the ID token
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,

    /// JWE `alg` the client requests for encrypting the ID token
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,

    /// JWE `enc` the client requests for encrypting the ID token; only valid
    /// alongside [`id_token_encrypted_response_alg`](Self::id_token_encrypted_response_alg)
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,

    /// JWS `alg` the client requests for signing `UserInfo` responses; if set,
    /// the response is returned as a signed JWT
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,

    /// JWE `alg` the client requests for encrypting `UserInfo` responses
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,

    /// JWE `enc` the client requests for encrypting `UserInfo` responses; only
    /// valid alongside [`userinfo_encrypted_response_alg`](Self::userinfo_encrypted_response_alg)
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,

    /// JWS `alg` the client requests for signing Request Objects, i.e. the JAR
    /// request object (RFC 9101 §10.5; `OpenID` Connect Dynamic Client
    /// Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,

    /// JWE `alg` the client requests for encrypting Request Objects
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,

    /// JWE `enc` the client requests for encrypting Request Objects; only valid
    /// alongside [`request_object_encryption_alg`](Self::request_object_encryption_alg)
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,

    /// JWS `alg` the client uses to sign the authentication JWT for the
    /// `private_key_jwt` and `client_secret_jwt` methods at the token endpoint
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,

    /// Default maximum authentication age, in seconds: if the end-user was last
    /// authenticated longer ago, they must be re-authenticated
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<u64>,

    /// Whether the `auth_time` claim is required in issued ID tokens
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,

    /// Default requested Authentication Context Class Reference (`acr`) values
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    pub default_acr_values: Vec<String>,

    /// `https` URI a third party can use to initiate a login at the client
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,

    /// `request_uri` values pre-registered for use at the authorization endpoint
    /// (`OpenID` Connect Dynamic Client Registration 1.0 §2).
    ///
    /// `OpenID` Connect Dynamic Client Registration 1.0
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    pub request_uris: Vec<String>,

    /// Extension metadata parameters beyond those typed above.
    #[serde(flatten)]
    #[builder(default)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Deserializes the `jwks` member through [`Jwks`](crate::core::jwk::Jwks)
/// (the only deserializable JWK Set type) and reduces it to a
/// [`PublicJwks`](crate::core::jwk::PublicJwks), so a server that echoes private
/// or symmetric material never lands in the public field.
mod jwks_serde {
    use serde::{Deserialize, Deserializer};

    use crate::core::jwk::{Jwks, PublicJwks};

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<PublicJwks>, D::Error> {
        Ok(Option::<Jwks>::deserialize(deserializer)?.map(PublicJwks::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_fields_are_absent_on_the_wire() {
        let metadata = ClientMetadata::builder().client_name("My App").build();
        let value = serde_json::to_value(&metadata).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(object.get("client_name").unwrap(), "My App");
        // Optionals and empty collections must not be serialized, so the
        // server fills its own defaults rather than seeing empty values.
        assert!(!object.contains_key("redirect_uris"));
        assert!(!object.contains_key("token_endpoint_auth_method"));
        assert!(!object.contains_key("grant_types"));
        assert!(!object.contains_key("jwks"));
    }

    #[test]
    fn software_statement_is_secret_on_the_type_but_plaintext_on_the_wire() {
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzb2Z0d2FyZV9pZCI6IngifQ.sig";
        let metadata = ClientMetadata::builder().software_statement(jwt).build();

        // Serializes to the raw JWT so the server receives a valid statement.
        let value = serde_json::to_value(&metadata).unwrap();
        assert_eq!(value.get("software_statement").unwrap(), jwt);

        // ...but is redacted from Debug so it cannot leak into logs.
        let debug = format!("{metadata:?}");
        assert!(
            !debug.contains(jwt),
            "software_statement leaked in Debug: {debug}"
        );

        // Round-trips back from the wire.
        let parsed: ClientMetadata = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.software_statement.unwrap().expose_secret(), jwt);
    }

    #[test]
    fn jwks_is_a_public_key_set_object_on_the_wire_and_round_trips() {
        let metadata = ClientMetadata::builder()
            .jwks(PublicJwks::new(vec![]))
            .build();

        let value = serde_json::to_value(&metadata).unwrap();
        assert!(value.get("jwks").unwrap().is_object());
        assert_eq!(value["jwks"]["keys"], serde_json::json!([]));

        // A server's echoed JWK Set object deserializes back into the typed field.
        let parsed: ClientMetadata =
            serde_json::from_value(serde_json::json!({ "jwks": { "keys": [] } })).unwrap();
        assert_eq!(parsed.jwks, Some(PublicJwks::new(vec![])));
    }

    #[test]
    fn oidc_dcr_parameters_are_typed_under_their_wire_names_and_round_trip() {
        let metadata = ClientMetadata::builder()
            .application_type("web")
            .request_object_signing_alg("ES256")
            .token_endpoint_auth_signing_alg("RS256")
            .default_max_age(3600)
            .require_auth_time(true)
            .default_acr_values(vec!["urn:mace:incommon:iap:silver".to_owned()])
            .request_uris(vec!["https://app.example/req/1".to_owned()])
            .build();

        let value = serde_json::to_value(&metadata).unwrap();
        // OIDC DCR parameters serialize under their spec wire names, not nested
        // under `extra`.
        assert_eq!(value["application_type"], "web");
        assert_eq!(value["request_object_signing_alg"], "ES256");
        assert_eq!(value["token_endpoint_auth_signing_alg"], "RS256");
        assert_eq!(value["default_max_age"], 3600);
        assert_eq!(value["require_auth_time"], true);
        assert_eq!(value["default_acr_values"], serde_json::json!(["urn:mace:incommon:iap:silver"]));
        assert_eq!(value["request_uris"], serde_json::json!(["https://app.example/req/1"]));

        // A server echo deserializes back into the typed fields, leaving `extra`
        // empty.
        let parsed: ClientMetadata = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.application_type.as_deref(), Some("web"));
        assert_eq!(parsed.request_object_signing_alg.as_deref(), Some("ES256"));
        assert_eq!(parsed.default_max_age, Some(3600));
        assert_eq!(parsed.require_auth_time, Some(true));
        assert!(parsed.extra.is_empty(), "typed fields must not fall into extra: {:?}", parsed.extra);
    }

    #[test]
    fn extension_parameters_round_trip_through_extra() {
        let json = serde_json::json!({
            "client_name": "My App",
            "redirect_uris": ["https://app.example/cb"],
            "example_extension_parameter": "value",
        });

        let metadata: ClientMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(metadata.client_name.as_deref(), Some("My App"));
        assert_eq!(metadata.redirect_uris, vec!["https://app.example/cb"]);
        assert_eq!(
            metadata.extra.get("example_extension_parameter").unwrap(),
            "value"
        );

        // Re-serializing keeps the extension parameter as a top-level member.
        let value = serde_json::to_value(&metadata).unwrap();
        assert_eq!(value.get("example_extension_parameter").unwrap(), "value");
    }
}
