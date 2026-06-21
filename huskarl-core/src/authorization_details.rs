//! RFC 9396 Rich Authorization Requests — the `authorization_details` parameter.

use std::collections::HashMap;

use bon::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single authorization details object (RFC 9396 §2).
///
/// `type` is the only field the library interprets — it identifies the
/// authorization details type and determines the meaning of the rest. Every
/// other field is defined by the protected API / authorization server and is
/// carried verbatim in [`fields`](Self::fields), so this type works with any
/// API without bespoke modelling.
///
/// ```
/// # use huskarl_core::AuthorizationDetail;
/// let detail = AuthorizationDetail::builder("payment_initiation")
///     .with("actions", serde_json::json!(["initiate", "status"]))
///     .with(
///         "instructedAmount",
///         serde_json::json!({ "currency": "EUR", "amount": "123.50" }),
///     )
///     .build();
/// assert_eq!(detail.r#type, "payment_initiation");
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Builder)]
pub struct AuthorizationDetail {
    /// The authorization details type identifier (RFC 9396 §2.1). Required; it
    /// determines the allowable contents of the rest of the object.
    #[builder(start_fn, into)]
    pub r#type: String,

    /// The type-specific fields — the RFC 9396 §2.2 common data fields
    /// (`locations`, `actions`, `datatypes`, `identifier`, `privileges`) and/or
    /// any API-specific extensions — carried verbatim.
    #[serde(flatten)]
    #[builder(field)]
    pub fields: HashMap<String, Value>,
}

impl<S: authorization_detail_builder::State> AuthorizationDetailBuilder<S> {
    /// Adds a type-specific field, returning the builder for chaining.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

impl TryFrom<Value> for AuthorizationDetail {
    type Error = serde_json::Error;

    /// Builds an authorization detail from a JSON object (e.g. one produced by
    /// `serde_json::to_value` of an API-specific typed struct). The object must
    /// contain a string `type` member.
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorizationDetail;
    use crate::oauth_form;

    fn sample() -> Vec<AuthorizationDetail> {
        vec![
            AuthorizationDetail::builder("account_information")
                .with(
                    "actions",
                    serde_json::json!(["list_accounts", "read_balances"]),
                )
                .build(),
            AuthorizationDetail::builder("payment_initiation")
                .with("actions", serde_json::json!(["initiate"]))
                .with(
                    "instructedAmount",
                    serde_json::json!({ "currency": "EUR", "amount": "123.50" }),
                )
                .build(),
        ]
    }

    #[test]
    fn form_value_is_a_json_array_round_trips() {
        // As carried in a query/body: a single JSON-text value (RFC 9396 §3).
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Req {
            authorization_details: Vec<AuthorizationDetail>,
        }
        let req = Req {
            authorization_details: sample(),
        };
        let form = oauth_form::to_string(&req).unwrap();
        assert_eq!(form.matches("authorization_details=").count(), 1, "{form}");
        assert!(form.contains("authorization_details=%5B%7B"), "{form}");
        assert_eq!(oauth_form::from_str::<Req>(&form).unwrap(), req);
    }

    #[test]
    fn json_value_is_a_native_array() {
        // As carried in a JAR request object / response: a native JSON array.
        let json = serde_json::to_value(sample()).unwrap();
        assert!(json.is_array());
        assert_eq!(json[0]["type"], "account_information");
        assert_eq!(json[1]["instructedAmount"]["currency"], "EUR");
    }

    #[test]
    fn try_from_value_requires_type() {
        let ok = AuthorizationDetail::try_from(serde_json::json!({
            "type": "x", "foo": 1
        }))
        .unwrap();
        assert_eq!(ok.r#type, "x");
        assert_eq!(ok.fields["foo"], serde_json::json!(1));

        assert!(AuthorizationDetail::try_from(serde_json::json!({ "foo": 1 })).is_err());
    }
}
