//! The [`from_metadata`](macro@from_metadata) attribute macro for the huskarl crates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

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
/// have the target type, so the conversion must succeed.
///
/// If a *required* grant field (not `Option<T>`) draws from an `Option`-typed
/// extraction, the generated function gates on it and returns
/// `Option<Builder<…>>`. At most one gating field per struct is supported.
///
/// The macro is generic over the metadata type — `metadata = …` names any
/// type, and the generated `builder_from_metadata(&Meta)` pre-fills the
/// tagged fields from it. The huskarl crates use it with
/// `AuthorizationServerMetadata`; here over a local struct:
///
/// ```rust
/// use bon::Builder;
///
/// struct Meta {
///     issuer: String,
///     endpoints: Option<Endpoints>,
/// }
///
/// struct Endpoints {
///     token: Option<String>,
/// }
///
/// #[huskarl_macros::from_metadata(metadata = Meta)]
/// #[derive(Builder)]
/// #[builder(state_mod(name = "builder"))]
/// struct Client {
///     #[from_metadata(path = "issuer")]
///     issuer: String,
///
///     // Each `?` marks an `Option` hop in the source.
///     #[from_metadata(path = "endpoints?.token?")]
///     token_endpoint: Option<String>,
/// }
///
/// let meta = Meta {
///     issuer: "https://as.example.com".into(),
///     endpoints: None,
/// };
/// let client = Client::builder_from_metadata(&meta).build();
/// assert_eq!(client.issuer, "https://as.example.com");
/// assert_eq!(client.token_endpoint, None);
/// ```
#[proc_macro_attribute]
pub fn from_metadata(args: TokenStream, input: TokenStream) -> TokenStream {
    from_metadata::expand(args.into(), input.into()).into()
}
