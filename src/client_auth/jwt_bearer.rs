use std::{sync::Arc, time::Duration};

use bon::Builder;
use http::Uri;

use crate::{
    client_auth::{AuthenticationParams, ClientAuthentication},
    crypto::signer::JwsSigningKey,
    jwt::{JwsSerializationError, SimpleJwt},
};

/// JWT Authentication (RFC 7521 / 7523 / `OpenID` Connect Core 1.0 §9)
///
/// With this method, the client authenticates using a JWT which has been
/// cryptographically signed.
///
/// The caller provides the client ID and signing implementation.
///
/// The implementation creates a JWT with these claims:
///  - iss (client ID)
///  - sub (client ID)
///  - aud (defaults to the token endpoint)
///  - exp (expiry time)
///  - iat (current time)
///  - jti (unique ID for replay protection)
///
/// ## Asymmetric private key
///
/// When the underlying key is an asymmetric private key, the code implements
/// RFC 7523 (private key JWT).
///
/// Benefits:
///  - no shared secrets
///  - stateless verification
///  - non-repudiation (proof that the client sent it)
///
/// ## HMAC shared key
///
/// When the underlying key is a symmetric HMAC key, the code implements
/// `OpenID` Connect Core 1.0 §9 (`client_secret_jwt`).
///
/// Benefits:
///  - simpler setup when a shared secret is acceptable
#[derive(Debug, Clone, Builder)]
pub struct JwtBearer<Sgn: JwsSigningKey> {
    /// The signer of the JWT.
    signer: Sgn,
    /// Sets the audience value for the bearer token.
    audience: Audience,
    /// The lifetime of the JWT (as set in the `exp` claim).
    #[builder(default = Duration::from_secs(60))]
    expires_after: Duration,
}

/// Sets the value used for the audience of the JWT.
///
/// This should be set to a value that is known to work for the particular
/// authorization server. Historically, the token endpoint was recommended
/// as the value for the audience. However, the issuer value may be safer,
/// especially when using authorization server metadata. The issuer value
/// is also required for FAPI 2.0.
///
/// Recommendation: if a particular value is known (and different to the
/// issuer or token endpoint), set it. If using authorization server
/// metadata, generally prefer the issuer value unless it fails to work
/// with your authorization server.
///
/// See <https://www.rfc-editor.org/rfc/rfc7523>,
/// <https://openid.net/specs/fapi-security-profile-2_0-final.html> and
/// <https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    PreferIssuer,
    PreferTokenEndpoint,
    Custom(Arc<str>),
}

impl<Sgn: JwsSigningKey> ClientAuthentication for JwtBearer<Sgn> {
    type Error = JwsSerializationError<Sgn::Error>;

    async fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        issuer: Option<&'a str>,
        token_endpoint: &'a Uri,
        _allowed_methods: Option<&'a [String]>,
    ) -> Result<super::AuthenticationParams<'a>, Self::Error> {
        let audience = match &self.audience {
            Audience::PreferIssuer => {
                issuer.map_or_else(|| token_endpoint.to_string(), ToString::to_string)
            }
            Audience::PreferTokenEndpoint => token_endpoint.to_string(),
            Audience::Custom(custom) => custom.to_string(),
        };

        let jwt = SimpleJwt::builder()
            .audience(audience)
            .issuer(client_id)
            .subject(client_id)
            .issued_now_expires_after(self.expires_after)
            .build();

        Ok(AuthenticationParams::builder()
            .form_params(bon::map! {
                "client_id": client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": jwt.to_jws_compact(&self.signer).await?
            })
            .build())
    }
}
