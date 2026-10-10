# Accepting API keys alongside OAuth tokens

Use [`PrefixRoutingValidator`](crate::validator::prefix_routing::PrefixRoutingValidator)
to route API keys with a reserved prefix to your key validator and other
credentials to an OAuth validator.

Two rules define the routing:

- **Prefixes must be exclusive.** Reserve prefixes that cannot occur at the
  beginning of OAuth access tokens. Registered prefixes must not overlap one another.
- **Validation failures never trigger fallback.** Once a validator is selected,
  its result is final. The fallback handles only credentials with no matching prefix.

This guide assumes you already have an API-key validator and an OAuth
access-token validator. For choosing an OAuth validator, see
[choosing a validator](crate::_docs::explanation::choosing_a_validator).

This guide covers API keys and OAuth tokens supplied through the same credential
header. To accept credentials from different headers, use a separate extraction
and routing layer.

## 1. Choose compatible validators

Both validators must implement
[`AccessTokenValidator`](crate::validator::AccessTokenValidator) and
[`ProvideValidatorMetadata`](crate::validator::metadata::ProvideValidatorMetadata)
and return the same claims type. Present API keys using the Bearer scheme:

```http
Authorization: Bearer hk_example123
```

Here, `hk_` is part of the credential, not the authentication scheme.

If the claims types differ, use
[`MapClaims`](crate::validator::multi_issuer::MapClaims) or
[`TryMapClaims`](crate::validator::multi_issuer::TryMapClaims) to map them to your
application's identity type, as shown in the [multi-issuer
guide](crate::_docs::guide::multi_issuer). If you are writing the key validator,
see [API-key validator requirements](#api-key-validator-requirements) below.

## 2. Register the prefix and fallback

With `api_keys` and `oauth` prepared, register the reserved prefix and fallback:

```rust
# use huskarl_resource_server::{
#     core::platform::MaybeSendSync,
#     validator::{
#         AccessTokenValidator,
#         metadata::ProvideValidatorMetadata,
#         multi_issuer::MultiIssuerValidator,
#         prefix_routing::PrefixRoutingBuildError,
#     },
# };
use huskarl_resource_server::validator::prefix_routing::PrefixRoutingValidator;
# fn credentials<C, V>(api_keys: V, oauth: MultiIssuerValidator<C>)
#     -> Result<PrefixRoutingValidator<C>, PrefixRoutingBuildError>
# where
#     C: MaybeSendSync + 'static,
#     V: AccessTokenValidator<Claims = C> + ProvideValidatorMetadata + 'static,
#     V::Error: 'static,
# {

let validator = PrefixRoutingValidator::builder()
    .prefix("hk_", "api_keys", api_keys)
    .fallback("oauth", oauth)
    .build()?;
# Ok(validator)
# }
```

| Situation | Behavior |
| --- | --- |
| Credential starts with `hk_` | Select the API-key validator. |
| Credential matches no prefix | Select the fallback, if configured. |
| Credential matches no prefix and there is no fallback | Reject with `invalid_token`. |
| Selected validator rejects the credential or its scheme | Return its failure; do not try another validator. |

The fallback can be a single-issuer validator or a `MultiIssuerValidator`.
Omit `.fallback(...)` to accept only credentials with registered prefixes.
Malformed presentations and schemes other than Bearer or DPoP are rejected
before routing, without calling any branch.

Prefix matching is case-sensitive. The builder rejects empty, duplicate, and
overlapping registered prefixes. **You must also ensure that reserved prefixes
cannot occur at the beginning of fallback credentials.** With an opaque-token
fallback such as
[`IntrospectionValidator`](crate::validator::introspection::IntrospectionValidator),
choose a prefix the authorization server's token format cannot produce. A matching
OAuth token would otherwise go to the API-key validator; rejection there will
not cause the router to try the OAuth fallback.

Use the same token header for the router and every branch. The router defaults
to `Authorization`; if you configure a different header, configure it on each
validator too, including the fallback. Reuse the same `HeaderName` value across
the builders to keep this configuration consistent.

All validators must read the same credential header. Otherwise, the router could
select a branch based on one credential while the selected validator authenticates
another. The router cannot reliably detect this mismatch.

A selected validator returning `Ok(None)` produces a server error because the
router has already found a credential. This catches only mismatches where the
branch reports no credential.

The router forwards the original request unchanged, so your key validator
receives the prefix, scheme, DPoP proof, target URI, and client certificate.

## 3. Observe validation failures

Wrap the router in
[`ObservedValidator`](crate::validator::observe::ObservedValidator) to observe
validation results. Use `ValidationEvent::branch_label` to identify the branch
on routed failures. Supply an explicit label for each branch with
`.prefix("hk_", "api_keys", api_keys)` and `.fallback("oauth", oauth)`.
You can share a label across branches to aggregate their failures.

For why branch labels are separate from issuer labels, see the
[error-model explanation](crate::_docs::explanation::error_handling#metrics-agree-with-the-wire).

Branch labels are safe to include in logs and metrics; do not record raw
credentials or DPoP proofs.

## API-key validator requirements

The router selects a validator; each validator remains responsible for
authenticating its credential. When implementing an API-key validator:

- Validate the full credential, including its prefix, before returning success.
  Return the authenticated identity and permissions as application claims;
  these can come from a database record rather than from the key itself.
- Enforce the authentication scheme and any sender constraints. The router
  accepts Bearer and DPoP presentations; provider-specific schemes such as
  `ApiKey` are unsupported. Reject DPoP presentation if your validator cannot
  validate the proof and key binding.
- Reserve `Ok(None)` for requests without a credential header. Return an error
  for credentials that are present but invalid or unsupported.

Implement `ProvideValidatorMetadata` so adapters can advertise the combined
capabilities. Leave `authorization_servers` absent if your keys have no
authorization server, and leave the validated request's `iss` absent if they
have no issuer.
