//! Reusable OAuth client configuration.

use std::sync::Arc;

use bon::Builder;

use crate::core::{
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
};

/// Client identity, authentication, and DPoP shared across grant types.
///
/// Apply with a grant builder's `client` method before setting any of those
/// three fields. Other grant settings retain their defaults and requirements.
/// Authentication and DPoP implementations are shared, including their state.
/// Use [`NoAuth`](crate::core::client_auth::NoAuth) for a public client.
///
/// ```
/// use huskarl::{
///     core::client_auth::NoAuth,
///     grant::{
///         ClientConfiguration, device_authorization::DeviceAuthorizationGrant,
///         refresh::RefreshGrant,
///     },
/// };
///
/// let client = ClientConfiguration::builder()
///     .client_id("my-client")
///     .client_auth(NoAuth)
///     .build();
/// let device = DeviceAuthorizationGrant::builder().client(&client);
/// let refresh = RefreshGrant::builder().client(&client);
/// // HTTP client and token endpoint are still required before build().
/// ```
#[derive(Clone, Builder)]
#[builder(on(String, into))]
pub struct ClientConfiguration {
    /// The registered OAuth client identifier.
    pub(crate) client_id: String,
    /// The client's authentication method, or [`NoAuth`](crate::core::client_auth::NoAuth) for a public client.
    #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
    pub(crate) client_auth: Arc<dyn ClientAuthentication>,
    /// The DPoP implementation. Defaults to [`NoDPoP`].
    #[builder(default = Arc::new(NoDPoP), with = |dpop: impl AuthorizationServerDPoP + 'static| Arc::new(dpop) as Arc<dyn AuthorizationServerDPoP>)]
    pub(crate) dpop: Arc<dyn AuthorizationServerDPoP>,
}

impl core::fmt::Debug for ClientConfiguration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientConfiguration")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}
