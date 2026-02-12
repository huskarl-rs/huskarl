//! Helper macros for the huskarl crate.

use proc_macro::TokenStream;

mod grant;
mod grant_impl;
mod grant_new;

/// Injects the seven common grant fields and generics into a grant struct.
///
/// Prepends `Auth: ClientAuthentication` and `D: AuthorizationServerDPoP = NoDPoP`
/// to the struct's generic parameters, followed by any generics already declared
/// on the struct.
///
/// Injects the following fields (with documentation) at the front of the struct:
/// `client_id`, `client_auth`, `dpop`, `issuer`, `token_endpoint`,
/// `mtls_token_endpoint`, and `token_endpoint_auth_methods_supported`.
///
/// # Arguments
///
/// - `vis(...)` — visibility of the injected common fields.
///   Defaults to private (inherited). Example: `#[grant(vis(pub(super)))]`.
///
/// # Mode 1: struct builder (struct has `#[derive(Builder)]`)
///
/// When the struct derives `Builder`, the macro additionally generates on the
/// bon builder:
///
/// - A `token_endpoint<U: IntoEndpointUrl>` setter
/// - A `with_common_metadata` method and `SetCommonMetadata` type alias
/// - `IntoEndpointUrl` setters for any fields annotated `#[endpoint_url]`
///   (optionality is inferred from the field type: `Option<EndpointUrl>` → both
///   `field_name` and `maybe_field_name` setters are generated)
///
/// ```ignore
/// #[huskarl_macros::grant]
/// #[derive(Debug, Clone, Builder)]
/// #[builder(state_mod(name = "builder"))]
/// pub struct ClientCredentialsGrant {
///     // only grant-specific fields here
/// }
/// ```
///
/// # Mode 2: function builder (struct has no `#[derive(Builder)]`)
///
/// When the struct does not derive `Builder` (because the builder comes from
/// `#[bon::bon]` + `async fn new`), only the common fields and generics are
/// injected. All setter and method generation is deferred to `#[grant_new]`
/// on the corresponding `impl` block.
///
/// ```ignore
/// #[huskarl_macros::grant(vis(pub(super)))]
/// #[derive(Clone)]
/// pub struct AuthorizationCodeGrant<J: Jar = NoJar> {
///     // only grant-specific fields here
/// }
///
/// #[huskarl_macros::grant_new]
/// #[bon::bon]
/// impl<Auth, D, J> AuthorizationCodeGrant<Auth, D, J> {
///     #[builder(state_mod(name = "builder"))]
///     pub async fn new(
///         #[endpoint_url] authorization_endpoint: EndpointUrl,
///     ) -> Result<Self, BoxedError> { ... }
/// }
/// ```
#[proc_macro_attribute]
pub fn grant(args: TokenStream, input: TokenStream) -> TokenStream {
    grant::expand(args.into(), input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Injects the seven common grant parameters into `async fn new` and generates
/// builder setters.
///
/// Apply to the `impl` block (alongside `#[bon::bon]`) containing `async fn new`.
/// The macro prepends the seven standard grant parameters — `client_id`,
/// `client_auth`, `dpop`, `issuer`, `token_endpoint`, `mtls_token_endpoint`,
/// and `token_endpoint_auth_methods_supported` — each with documentation.
///
/// Also generates on the bon builder:
///
/// - A `token_endpoint<U: IntoEndpointUrl>` setter
/// - A `with_common_metadata` method and `SetCommonMetadata` type alias
/// - `IntoEndpointUrl` setters for any parameters annotated `#[endpoint_url]`
///   (optionality inferred from the parameter type)
///
/// Intended for use alongside `#[grant]` on the struct (Mode 2), which injects
/// the corresponding common struct fields.
///
/// ```ignore
/// #[huskarl_macros::grant_new]
/// #[bon::bon]
/// impl<Auth, D, J> AuthorizationCodeGrant<Auth, D, J> {
///     #[builder(state_mod(name = "builder"))]
///     pub async fn new(
///         #[endpoint_url] authorization_endpoint: EndpointUrl,
///         #[endpoint_url] pushed_authorization_request_endpoint: Option<EndpointUrl>,
///         redirect_uri: String,
///     ) -> Result<Self, BoxedError> {
///         Ok(Self { /* ... */ })
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn grant_new(_args: TokenStream, input: TokenStream) -> TokenStream {
    grant_new::expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Fills in the common `OAuth2ExchangeGrant` method bodies for a grant impl block.
///
/// Injects implementations for: `client_id`, `issuer`, `client_auth`,
/// `token_endpoint`, `mtls_token_endpoint`, `dpop`, and `allowed_auth_methods`.
///
/// Methods already present in the impl block are left untouched, so any of
/// the common methods can be overridden by providing your own implementation.
///
/// ```ignore
/// #[huskarl_macros::grant_impl]
/// impl<Auth: ClientAuthentication + Clone + 'static, D: AuthorizationServerDPoP + 'static>
///     OAuth2ExchangeGrant for ClientCredentialsGrant<Auth, D>
/// {
///     type Parameters = ClientCredentialsGrantParameters;
///     type ClientAuth = Auth;
///     type DPoP = D;
///     type Form<'a> = ClientCredentialsGrantForm;
///
///     fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> { ... }
///     fn to_refresh_grant(&self) -> RefreshGrant<Auth, D> { ... }
///     // common methods are injected automatically
/// }
/// ```
#[proc_macro_attribute]
pub fn grant_impl(args: TokenStream, input: TokenStream) -> TokenStream {
    grant_impl::expand(args.into(), input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
