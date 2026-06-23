//! Provider-agnostic types describing what a test wants from an authorization
//! server, and what it gets back. [`Features`] drives the matrix.

use bitflags::bitflags;
use bon::Builder;
use huskarl_core::jwk::PublicJwk;

bitflags! {
    /// A set of OAuth2/OIDC features. A flow runs iff its required features are
    /// a subset of the provider's supported set.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Features: u32 {
        /// RFC 6749 §4.4
        const CLIENT_CREDENTIALS = 1 << 0;
        /// RFC 7636
        const AUTH_CODE = 1 << 1;
        /// RFC 8628
        const DEVICE = 1 << 2;
        /// RFC 6749 §6
        const REFRESH = 1 << 3;
        /// RFC 7662
        const INTROSPECTION = 1 << 4;
        /// RFC 9449
        const DPOP = 1 << 5;
        /// RFC 8705
        const MTLS = 1 << 6;
        /// RFC 9126
        const PAR = 1 << 7;
        /// RFC 9101
        const JAR = 1 << 8;
        /// RFC 7523 / OIDC Core §9; requires a registered `signing_jwk`.
        const PRIVATE_KEY_JWT = 1 << 9;
    }
}

/// Which transport to obtain an issuer / tokens over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Plain,
    Mtls,
}

/// A provider-agnostic request to provision a test client.
#[derive(Debug, Clone, Builder)]
#[builder(on(String, into))]
pub struct ClientSpec {
    pub features: Features,

    /// Requested `aud` for issued tokens.
    pub audience: Option<String>,

    #[builder(default)]
    pub redirect_uris: Vec<String>,

    /// Public JWK to register (JAR / `private_key_jwt`); `None` if not signing.
    pub signing_jwk: Option<PublicJwk>,
}

/// A client provisioned by a [`TestProvider`](crate::TestProvider).
#[derive(Debug, Clone)]
pub struct ProvisionedClient {
    pub client_id: String,
    /// `None` for public clients.
    pub secret: Option<String>,
    pub redirect_uris: Vec<String>,
}

/// Certificate material for driving an mTLS flow.
#[derive(Debug, Clone)]
pub struct MtlsMaterial {
    /// CA certificate (PEM).
    pub ca_pem: Vec<u8>,
    /// Client certificate and private key concatenated (PEM).
    pub client_identity_pem: String,
    /// Client certificate alone (PEM); drives the `cnf.x5t#S256` check.
    pub client_cert_pem: String,
}
