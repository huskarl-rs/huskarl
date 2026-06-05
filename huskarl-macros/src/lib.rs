//! Helper macros for the huskarl crate.

use proc_macro::TokenStream;

mod from_metadata;
mod try_builder;
mod util;

/// Generates fallible setters on a `bon`-derived builder.
///
/// For each field annotated `#[try_setter(Trait::method)]`, the macro injects
/// `#[builder(setters(vis = "", name = "{field}_internal"))]` to hide bon's
/// default setter, then emits a public setter on `{Struct}Builder` that takes
/// any `U: Trait`, calls `Trait::method(value)?`, and forwards the converted
/// value to the hidden internal setter.
///
/// The trait is generic — the same macro covers `IntoEndpointUrl`,
/// `IntoDuration`, `IntoSecret`, etc. The setter returns
/// `Result<Builder<…>, <U as Trait>::Error>` so the caller sees the converter's
/// own error type unchanged.
///
/// `Option<T>` fields receive an additional `maybe_{field}` setter taking
/// `Option<U>`.
///
/// Apply *before* `#[derive(bon::Builder)]` so the injected `#[builder(...)]`
/// attribute is visible to bon's derive. Currently assumes
/// `#[builder(state_mod(name = "builder"))]`.
///
/// ```ignore
/// #[huskarl_macros::try_builder]
/// #[derive(bon::Builder)]
/// #[builder(state_mod(name = "builder"))]
/// struct Foo {
///     #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
///     url: crate::core::EndpointUrl,
///
///     #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
///     mtls_url: Option<crate::core::EndpointUrl>,
/// }
/// ```
#[proc_macro_attribute]
pub fn try_builder(args: TokenStream, input: TokenStream) -> TokenStream {
    let args: proc_macro2::TokenStream = args.into();
    let input: proc_macro2::TokenStream = input.into();

    let error = if args.is_empty() {
        match try_builder::expand(input.clone()) {
            Ok(ts) => return ts.into(),
            Err(err) => err,
        }
    } else {
        syn::Error::new_spanned(&args, "#[try_builder] takes no arguments")
    };

    // Re-emit the item (minus our helper attributes) alongside the error so
    // the type still exists and use sites don't cascade into "cannot find
    // type" diagnostics.
    let mut out = error.into_compile_error();
    out.extend(util::strip_helper_attrs_and_reemit(input, &["try_setter"]));
    out.into()
}

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
/// Fields that *also* have `#[try_setter]` go through bon's `_internal`
/// setters so the value bypasses the fallible conversion. The macro reads
/// `#[try_setter]` without consuming it; `#[try_builder]` consumes it later.
///
/// If a *required* grant field (not `Option<T>`) draws from an `Option`-typed
/// extraction, the generated function gates on it and returns
/// `Option<Builder<…>>`. At most one gating field per struct is supported.
///
/// Apply *outside* `#[try_builder]`, since this macro reads `#[try_setter]`
/// attributes on fields:
///
/// ```ignore
/// #[huskarl_macros::from_metadata(crate::core::server_metadata::AuthorizationServerMetadata)]
/// #[huskarl_macros::try_builder]
/// #[derive(bon::Builder)]
/// #[builder(state_mod(name = "builder"))]
/// pub struct Foo<…> {
///     #[from_metadata(path = "issuer")]
///     issuer: Option<String>,
///
///     #[from_metadata(path = "token_endpoint")]
///     #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
///     token_endpoint: crate::core::EndpointUrl,
///
///     #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
///     #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
///     mtls_token_endpoint: Option<crate::core::EndpointUrl>,
/// }
/// ```
#[proc_macro_attribute]
pub fn from_metadata(args: TokenStream, input: TokenStream) -> TokenStream {
    from_metadata::expand(args.into(), input.into()).into()
}
