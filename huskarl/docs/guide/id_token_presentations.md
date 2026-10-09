# Validate an ID-token presentation

Use `IdTokenPresentationValidator` when a component of your relying party
receives a key-bound ID token and proof from another component. Continue to use
`IdTokenValidator` for the response from the OP during authentication.

[OpenID Connect Key Binding draft 03](https://openid.net/specs/openid-connect-key-binding-1_0-03.html)
requires consuming components to validate the ID token and possession of the
bound key, but leaves the presentation proof protocol unspecified. Configure
an implementation of `IdTokenPresentationProofVerifier` for your application's
protocol. No default proof verifier or new wire protocol is supplied.

```rust
use huskarl::{
    core::crypto::verifier::JwsVerifier,
    token::{
        IdToken,
        id_token_presentation::{
            IdTokenPresentationError, IdTokenPresentationProofVerifier,
            IdTokenPresentationValidator, VerifiedIdTokenPresentation,
        },
    },
};

async fn accept<P: IdTokenPresentationProofVerifier>(
    op_verifier: impl JwsVerifier + 'static,
    proof_verifier: P,
    token: &IdToken,
    proof: &P::Proof,
    context: &P::Context,
) -> Result<VerifiedIdTokenPresentation, IdTokenPresentationError> {
    let validator = IdTokenPresentationValidator::builder()
        .verifier(op_verifier)
        .issuer("https://issuer.example")
        .audiences(["mobile-client-id".to_owned(), "desktop-client-id".to_owned()])
        .allowed_algorithms(["ES256".to_owned()])
        .proof_verifier(proof_verifier)
        .build();

    validator.validate(token, proof, context).await
}
```

Configure the issuer and OP verification keys from trusted application
configuration or discovery. The audiences are originating client IDs that this
component serves within the same RP, not the component's URL. At least one must
match the token's `aud`; an empty allowlist accepts nothing. Additional audiences
are not rejected by this consumer policy. Use a separate configured validator
for each issuer and its associated client IDs.

The validator requires an OP-signed token with a subject, expiry, issuance time,
and `typ: dpop+id_token`. It checks temporal claims and any configured OP
algorithm allowlist. It does not compare the original authentication nonce
against a presentation challenge, or require access to the initial authorization
request. The proof verifier checks the binding and possession of its key.

The proof verifier receives the exact compact ID token, the submitted proof,
and the consumer's context. It must:

- Extract the token's public key with
  [`binding_key`](crate::token::id_token_presentation::binding_key), propagating
  any error before accessing replay state. The helper checks the binding
  structure; it does not authenticate
  the token. It rejects unsupported confirmation forms, private key material
  and `x5u` references. The validator has already checked the OP signature and
  claims.
- Verify the proof with the bound key and the protocol's allowed algorithms.
- Bind the proof to the token and intended interaction, as specified by that
  protocol, so another token or interaction cannot be substituted.
- Enforce freshness and replay protection, such as an expiring challenge
  consumed atomically after all proof checks pass.
- Fail if any required verification or replay-storage operation fails.
- Return `Ok(())` only after all checks succeed.

A valid signature alone is insufficient. In particular, merely invoking the
resource server's structural `DPoPProofValidator` does not fulfill this contract.
Share replay protection state across requests and consumer instances as required
by the deployment; recreating a verifier must not reset the replay defense.

On success, the result records that the proof was accepted and `claims()` exposes
the verified identity. Authorization remains an application policy decision. The result applies to that presentation context and must not
be treated as a reusable proof for later requests. ID tokens stay within the RP
trust boundary and are not access tokens for protected resources.

This API does not add binding checks to token-endpoint responses.
