# Handling keys from untrusted sources

A JWK can arrive from a trusted channel (an authorization server's published
JWKS, fetched over TLS) or an untrusted one (a `DPoP` proof header supplied by
the client). The [`jwk`](crate::jwk) types parse both, but the X.509-related
parameters defined by RFC 7517 §4.6–4.9 carry security weight, so this library
treats them conservatively rather than acting on them.

## X.509 certificate parameters (`x5c`, `x5t`, `x5t#S256`, `x5u`)

- **`x5u`** (X.509 URL) — captured and **rejected** when present in JWKs from
  untrusted sources such as `DPoP` proof headers (RFC 9449 §4.2). Like `jku` in
  JWS headers, `x5u` triggers a remote fetch, which introduces SSRF risk and
  lets an attacker substitute their own key material. Per RFC 7517 §4.6 the
  referenced resource must be secured, but that cannot be verified at parse
  time, so rejection is the safe default.

- **`x5c`** (X.509 certificate chain) — silently ignored. Certificate-chain
  validation against trust anchors is not implemented; the key material (`n`,
  `e`, `x`, `y`, …) is used directly. Some providers (e.g. Microsoft Entra)
  include `x5c` in their JWKS — harmless here, since the signing key material is
  present regardless.

- **`x5t`** (X.509 SHA-1 thumbprint) — silently ignored. SHA-1 is deprecated for
  cryptographic use (RFC 6151) and this field adds no security without
  certificate-chain validation.

- **`x5t#S256`** (X.509 SHA-256 thumbprint) — silently ignored at the JWK level.
  Note that `cnf.x5t#S256` in JWT access tokens is a distinct concept (RFC 8705
  §4), handled separately by the resource-server validator.

The guiding rule: a parameter that would cause an outbound request or imply a
trust decision is rejected; one that is merely redundant metadata is ignored.
