//! Helper macros for the huskarl crate.

use proc_macro::TokenStream;

mod from_metadata;
mod util;

/// Generates `builder_from_metadata` on a struct whose fields are tagged
/// `#[from_metadata(path = "…")]` or `#[from_metadata(with = |m| …)]`.
///
/// Per-field syntax:
///
/// - `path = "a.b.c"` — dotted path navigated from the metadata reference;
///   each segment may be suffixed `?` to mark it as `Option`. The macro emits
///   `.as_ref().and_then(…)` / `.as_ref().map(…)` chains as needed and adds a
///   final `.clone()`.
/// - `with = |m| <expr>` — escape hatch; the closure body is the extraction
///   expression. Used when the source needs computation. By default the
///   closure is assumed to yield `T`; add `maybe` (e.g. `with = |m| …, maybe`)
///   when the closure yields `Option<T>` and you want bon's `maybe_*` setter
///   (or to gate a required field on the closure result).
///
/// Extractions run in alphabetical field-name order (the generated builder
/// state chain is sorted by name so it stays stable across field
/// reorderings), not declaration order. Keep `with` closures free of order
/// dependence; they should be pure projections of the metadata.
///
/// Fields whose bon setter is a fallible `with` closure
/// (`#[builder(with = |…| -> Result<…> { … })]`) are routed through that
/// setter and the `Result` is unwrapped (`.expect`). Metadata fields already
/// have the target type, so the conversion must be an infallible identity
/// case (e.g. `impl IntoEndpointUrl for EndpointUrl` returns `Ok(self)`).
///
/// If a *required* grant field (not `Option<T>`) draws from an `Option`-typed
/// extraction, the generated function gates on it and returns
/// `Option<Builder<…>>`. At most one gating field per struct is supported.
///
/// ```ignore
/// #[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
/// #[derive(bon::Builder)]
/// #[builder(state_mod(name = "builder"))]
/// pub struct Foo {
///     #[from_metadata(path = "issuer")]
///     issuer: Option<String>,
///
///     #[from_metadata(path = "token_endpoint")]
///     #[builder(with = |url: impl IntoEndpointUrl| -> Result<_, Error> {
///         IntoEndpointUrl::into_endpoint_url(url)
///     })]
///     token_endpoint: crate::core::EndpointUrl,
///
///     #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
///     #[builder(with = |url: impl IntoEndpointUrl| -> Result<_, Error> {
///         IntoEndpointUrl::into_endpoint_url(url)
///     })]
///     mtls_token_endpoint: Option<crate::core::EndpointUrl>,
/// }
/// ```
#[proc_macro_attribute]
pub fn from_metadata(args: TokenStream, input: TokenStream) -> TokenStream {
    from_metadata::expand(args.into(), input.into()).into()
}
