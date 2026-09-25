# ID tokens and sign-in state across refreshes

A refresh obtains new tokens using an existing authorization. It does not mean
the user has signed in again. This distinction matters when an application
needs both an access token and an ID token, or limits how long a sign-in remains
acceptable.

## Token expiry and authentication age

An ID token's expiry determines how long that token can be accepted. A refreshed
ID token has its own expiry and issuance time. Its optional `auth_time` claim
records a different event: when the user originally signed in. Issuing a new
token does not reset that time.

[`IdTokenValidator`](crate::token::id_token::IdTokenValidator)'s `max_age` setting
limits the time since that sign-in. For example, a validator configured with a
five-minute limit rejects a refreshed token after the sign-in becomes older
than five minutes, allowing for clock leeway, even if the token was just issued.
Reusing a validator with this setting therefore applies the limit to ongoing
refreshes as well as initial validation. Applications should choose whether they
want that ongoing requirement when configuring their refresh validator.

Providers do not always include the sign-in timestamp. When `max_age` is
configured, validation requires it so the age can be checked. Without that
setting, a token may be accepted without a timestamp. If both the original and
refreshed tokens contain it, `validate_refresh` requires them to agree. If only
the refreshed token contains it, there is no original timestamp to compare.

## Why retain the original claims?

Refresh validation checks the new token against the identity established at
the initial sign-in: the provider, user, and intended recipients must remain
the same. The original validated claims are the reference for those checks;
they remain useful after the original token expires.

Optional claims can disappear in a refresh. In particular, a refreshed token
can omit the nonce that linked the initial token to the sign-in request. If an
application replaced its original reference with those refreshed claims, it
would lose the nonce needed to check a later token that includes it again.
Keep the initial validated claims separately from the latest tokens.

## A successful refresh may omit the ID token

[OIDC Core §12.2](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse)
allows a successful refresh response to omit an ID token. An application may
therefore obtain a usable access token without obtaining a fresh identity token
for a downstream exchange. Retaining the original claims does not extend the
original ID token's validity or produce a replacement token.

The application decides how to handle that outcome for its integration.
`validate_refresh` checks a supplied token; it does not acquire tokens, retain
session state, or make the cache guarantee an ID token is available.

See [Validate an ID token returned by
refresh](crate::_docs::guide::refresh#validate-an-id-token-returned-by-refresh)
for the validation steps and [the API
reference](crate::token::id_token::IdTokenValidator::validate_refresh) for the
exact validation contract.
