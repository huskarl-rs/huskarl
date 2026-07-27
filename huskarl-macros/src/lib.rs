//! Procedural macros for the huskarl crates.
//!
//! Use [`Classify`] to derive error propagation and
//! [`from_metadata`](macro@from_metadata) to build configuration from metadata.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use proc_macro::TokenStream;

mod classify;
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
/// `Result<Builder<…>, huskarl_core::Error>` whose message names the absent
/// field. At most one gating field per struct is supported.
///
/// Gated code names `::huskarl_core`, so a struct with a gating field must be in
/// a crate depending on `huskarl-core` under its default name. Ungated
/// invocations (like the example below) have no such requirement.
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

/// Derives `huskarl_core::error::propagation::Cause` and a conversion to
/// `huskarl_core::Error` for an enum.
///
/// Each variant either propagates an existing huskarl error or establishes a
/// new classification. A variant propagates when it has a field whose type is
/// bare `Error` or `<huskarl-core dependency>::Error`. The derive resolves the
/// dependency name from `Cargo.toml`, so aliases are supported.
///
/// Variants that do not propagate an error must have exactly one of:
///
/// - `#[classify(no)]`: retrying will not help.
/// - `#[classify(retry)]`: the same operation may succeed later.
/// - `#[classify(with = path)]`: call `path` with references to the fields, in
///   declaration order. The function returns
///   `huskarl_core::error::propagation::Origin` and chooses whether to establish
///   a classification or propagate a nested `Error`.
///
/// ```rust
/// use std::fmt;
///
/// use huskarl_core::{Error, RetryAdvice, error::propagation::Origin};
/// use huskarl_macros::Classify;
///
/// #[derive(Debug, Classify)]
/// enum RequestCause {
///     #[classify(no)]
///     InvalidRequest,
///     #[classify(retry)]
///     Unavailable,
///     #[classify(with = RequestCause::classify_status)]
///     Response {
///         status: u16,
///     },
///     Wrapped(Error),
/// }
///
/// impl RequestCause {
///     fn classify_status(status: &u16) -> Origin<'_> {
///         let advice = match status {
///             429 => RetryAdvice::RETRY.into(),
///             _ => RetryAdvice::No.into(),
///         };
///         Origin::Establishes(advice)
///     }
/// }
///
/// impl fmt::Display for RequestCause {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         f.write_str("request failed")
///     }
/// }
///
/// impl std::error::Error for RequestCause {}
///
/// let error: Error = RequestCause::Unavailable.into();
/// assert_eq!(error.retry_advice(), RetryAdvice::RETRY);
///
/// let inner = Error::new(RetryAdvice::No, "invalid response");
/// let error: Error = RequestCause::Wrapped(inner).into();
/// assert_eq!(error.retry_advice(), RetryAdvice::No);
/// ```
///
/// The generated implementations preserve type, lifetime, and const generics,
/// including bounds and `where` clauses. The derive adds no bounds: the enum
/// itself must satisfy `Cause`, including `std::error::Error`, `'static`, and
/// the platform's send/sync requirements.
///
/// # Limitations
///
/// - Only enums are supported.
/// - Propagation detection is syntactic. Type aliases, nested types, and other
///   paths ending in `Error` are not recognized. Bare `Error` is assumed to be
///   `huskarl_core::Error`.
/// - A propagating variant cannot also have `#[classify(...)]`. If several
///   fields have a recognized error type, the first one is propagated.
/// - The generated `Cause` or `From` implementation must not conflict with an
///   existing implementation.
#[proc_macro_derive(Classify, attributes(classify))]
pub fn classify(input: TokenStream) -> TokenStream {
    classify::expand(input.into()).into()
}
