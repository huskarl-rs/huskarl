//! `#[from_metadata(MetadataType)]` — generates `builder_from_metadata` on a
//! struct whose fields are annotated with `#[from_metadata(...)]`.
//!
//! Per-field syntax:
//! - `#[from_metadata(path = "a.b.c")]` — dotted path; mark any segment with a
//!   trailing `?` to navigate through `Option` (e.g. `"mtls_aliases?.token_endpoint?"`).
//!   The macro emits `metadata.a.as_ref().and_then(|a| …)` for `?` non-leaves and
//!   `.map` when the rest of the path is non-Option. Segments must be plain
//!   (non-keyword, non-raw) Rust identifiers.
//! - `#[from_metadata(with = |m| <expr>)]` — escape hatch; the closure body
//!   becomes the extraction expression. By default the macro treats the
//!   closure as yielding `T` (bon's non-`maybe_` setter is called). Add the
//!   bare `maybe` flag — `#[from_metadata(with = |m| …, maybe)]` — to declare
//!   that the closure yields `Option<T>` instead; the macro then routes
//!   through bon's `maybe_*` setter (and can also gate a required field).
//!
//! Fields whose bon setter is a fallible `with` closure
//! (`#[builder(with = |…| -> Result<…> { … })]`) are routed through that
//! setter and the `Result` is unwrapped (`.expect`): metadata fields already
//! have the target type, so the conversion is required to succeed.
//!
//! Gating: if exactly one *required* field (not `Option<T>`) draws from an
//! Option-typed extraction, the generated function returns
//! `Result<Builder<…>, huskarl_core::Error>` and the body is wrapped in
//! `.as_ref().map(|x| …).ok_or_else(…)`, the error naming the absent field.
//! Multiple gates aren't supported. Only this branch names `::huskarl_core`;
//! ungated invocations stay dependency-free.

use darling::{FromMeta, ast::NestedMeta};
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    Attribute, Expr, ExprClosure, Field, Fields, FnArg, GenericParam, Ident, ImplItem, Item,
    ItemImpl, ItemStruct, Pat, PatType, Path, Result, Token, Visibility, parse2,
    punctuated::Punctuated,
};

use crate::util::{
    deny_raw_ident, is_option_type, pascal_case, split_generics, split_self_type, start_fn_ident,
    state_mod_ident,
};

/// Top-level args for `#[from_metadata(...)]`, parsed by darling.
///
/// Schema:
/// - `metadata = path::to::MetadataType` — required.
/// - `method(name = "...", vis = "...")` — optional; defaults to `builder_from_metadata` / `pub`.
///   Mirrors bon's `start_fn(name = "...", vis = "...")` shape so the two
///   macros' config surfaces look consistent.
#[derive(FromMeta)]
struct MacroArgs {
    metadata: Path,
    #[darling(default)]
    method: MethodConfig,
}

#[derive(Default, FromMeta)]
struct MethodConfig {
    /// Parsed by darling as an identifier so an invalid name (`"not an ident"`)
    /// is a spanned error at the attribute, not an `Ident::new` panic.
    #[darling(default)]
    name: Option<Ident>,
    #[darling(default)]
    vis: Option<Visibility>,
}

/// Resolved method config, with defaults filled in.
struct ResolvedMethod {
    name: Ident,
    vis: Visibility,
}

impl MethodConfig {
    fn resolve(self) -> ResolvedMethod {
        let name = self
            .name
            .unwrap_or_else(|| Ident::new("builder_from_metadata", Span::call_site()));
        let vis = self.vis.unwrap_or_else(|| syn::parse_quote!(pub));
        ResolvedMethod { name, vis }
    }
}

fn parse_macro_args(args: TokenStream) -> darling::Result<(Path, ResolvedMethod)> {
    let nested = NestedMeta::parse_meta_list(args)?;
    let parsed = MacroArgs::from_list(&nested)?;
    Ok((parsed.metadata, parsed.method.resolve()))
}

/// Macro entry point. Returns a `TokenStream` directly (never `Result`) so we
/// can emit darling's span-preserving `compile_error!` invocations alongside
/// any `syn::Error::to_compile_error()` from later stages.
///
/// On error, the annotated item is re-emitted (minus our `#[from_metadata]`
/// field attributes) so the type still exists.
pub fn expand(args: TokenStream, input: TokenStream) -> TokenStream {
    match expand_inner(args, input.clone()) {
        Ok(ts) => ts,
        Err(err) => {
            let mut out = err.write_errors();
            out.extend(crate::util::strip_helper_attrs_and_reemit(
                input,
                &["from_metadata"],
            ));
            out
        }
    }
}

fn expand_inner(args: TokenStream, input: TokenStream) -> darling::Result<TokenStream> {
    let (metadata_type, method) = parse_macro_args(args)?;

    let item: Item = parse2(input).map_err(darling::Error::from)?;
    match item {
        Item::Struct(s) => expand_struct(s, metadata_type, method).map_err(Into::into),
        Item::Impl(i) => expand_impl(i, metadata_type, method).map_err(Into::into),
        other => Err(darling::Error::custom(
            "#[from_metadata] applies to a struct (with `#[derive(Builder)]`) or to an impl block (with `#[bon::bon]` + `#[builder]` on a `fn new`)",
        )
        .with_span(&other)),
    }
}

fn expand_struct(
    mut item: ItemStruct,
    metadata_type: Path,
    method: ResolvedMethod,
) -> Result<TokenStream> {
    let Fields::Named(ref mut fields) = item.fields else {
        return Err(syn::Error::new_spanned(
            &item.ident,
            "#[from_metadata] requires a struct with named fields",
        ));
    };

    let mut metadata_fields: Vec<MetadataField> = Vec::new();
    for field in fields.named.iter_mut() {
        if let Some(mf) = MetadataField::from_field(field)? {
            metadata_fields.push(mf);
        }
    }

    let state_mod = state_mod_ident(&item.ident, &item.attrs)?;
    let start_fn = start_fn_ident(&item.attrs)?;
    // Struct mode: bon's builder shares the struct's full generic signature,
    // and the impl target is `{Struct}<…same params…>`, so both type-arg
    // lists are identical.
    let (_, type_args) = split_generics(&item.generics);
    let body = emit_impl(
        &item.ident,
        &state_mod,
        &start_fn,
        &item.generics,
        &type_args,
        &type_args,
        &metadata_type,
        &method,
        metadata_fields,
    )?;

    Ok(quote! {
        #item
        #body
    })
}

/// Impl-block mode: looks for `#[from_metadata(...)]` on the arguments of
/// `fn new` inside `#[bon::bon]` impl blocks. The generated
/// `builder_from_metadata` static method lives on the struct type, just as in
/// struct mode.
fn expand_impl(
    mut item: ItemImpl,
    metadata_type: Path,
    method: ResolvedMethod,
) -> Result<TokenStream> {
    // The impl target uses `Self`'s literal args (so `impl<T> Foo<u32, T>`
    // keeps the `u32`); bon's builder, on the other hand, only sees the impl's
    // own generic parameter list (no `u32`), so we plumb both lists.
    let (struct_ident, self_type_args) = split_self_type(&item.self_ty, "from_metadata")?;
    let impl_generics = item.generics.clone();
    let (_, builder_type_args) = split_generics(&impl_generics);

    let fn_new = find_fn_new_mut(&mut item)?;

    let mut metadata_fields: Vec<MetadataField> = Vec::new();
    for arg in fn_new.sig.inputs.iter_mut() {
        if let FnArg::Typed(typed) = arg
            && let Some(mf) = MetadataField::from_fn_arg(typed)?
        {
            metadata_fields.push(mf);
        }
    }

    let state_mod = state_mod_ident(&struct_ident, &fn_new.attrs)?;
    let start_fn = start_fn_ident(&fn_new.attrs)?;
    let body = emit_impl(
        &struct_ident,
        &state_mod,
        &start_fn,
        &impl_generics,
        &self_type_args,
        &builder_type_args,
        &metadata_type,
        &method,
        metadata_fields,
    )?;

    Ok(quote! {
        #item
        #body
    })
}

/// Builds the `impl<…> Struct<…> { fn builder_from_metadata(…) -> … }` block.
/// Shared between struct and impl modes; the caller has already done the
/// mode-specific work of gathering `MetadataField`s and stripping our
/// per-element attributes.
#[allow(clippy::too_many_arguments)] // internal fn fed by two thin mode-specific frontends
fn emit_impl(
    struct_ident: &Ident,
    state_mod: &Ident,
    start_fn: &Ident,
    generics: &syn::Generics,
    self_type_args: &TokenStream,
    builder_type_args: &TokenStream,
    metadata_type: &Path,
    method: &ResolvedMethod,
    mut metadata_fields: Vec<MetadataField>,
) -> Result<TokenStream> {
    if metadata_fields.is_empty() {
        return Err(syn::Error::new_spanned(
            struct_ident,
            "#[from_metadata(...)] applied with no `#[from_metadata]` element attributes",
        ));
    }

    // Sort by name so the generated `Set{Field}<…>` chain is stable across
    // field/argument reorderings. Bon's state wrappers compose commutatively
    // at `.build()`, so changing iteration order only affects the type's
    // *name*, not its semantics.
    metadata_fields.sort_by(|a, b| a.field_ident.cmp(&b.field_ident));

    let gate_indices: Vec<usize> = metadata_fields
        .iter()
        .enumerate()
        .filter_map(|(i, f)| f.is_gate().then_some(i))
        .collect();
    if gate_indices.len() > 1 {
        return Err(syn::Error::new_spanned(
            struct_ident,
            "#[from_metadata] currently supports at most one gating field \
             (a required field whose source is Option in metadata)",
        ));
    }
    let gate_idx = gate_indices.first().copied();
    let gate = gate_idx.map(|i| &metadata_fields[i]);

    let builder_ident = format_ident!("{}Builder", struct_ident);
    let metadata_var = Ident::new("metadata", proc_macro2::Span::call_site());

    let state_chain = build_state_chain(state_mod, &metadata_fields);
    let setter_chain = build_setter_chain(&metadata_var, &metadata_fields, gate);

    let body = if let Some(gate) = gate {
        // Prefixed binding: naming it after the field would shadow the
        // `metadata` parameter inside the closure for a field named
        // `metadata`, corrupting every other extraction.
        let gate_var = Ident::new("__huskarl_gate", gate.field_ident.span());
        let outer_extract = match &gate.extraction {
            Extraction::Path(segs) => path_root_for_gate(&metadata_var, segs),
            // `metadata_var` is already `&Metadata`; pass it through unchanged
            // so the closure sees the same `&Metadata` as in non-gate position.
            Extraction::With { closure, .. } => quote! { (#closure)(#metadata_var) },
        };
        let missing_field = gate_field_name(gate);
        quote! {
            #outer_extract
                .as_ref()
                .map(|#gate_var| {
                    Self::#start_fn() #setter_chain
                })
                .ok_or_else(|| ::huskarl_core::server_metadata::missing_field(#missing_field))
        }
    } else {
        quote! { Self::#start_fn() #setter_chain }
    };

    let return_ty = if gate.is_some() {
        quote! {
            ::core::result::Result<
                #builder_ident<#builder_type_args #state_chain>,
                ::huskarl_core::Error,
            >
        }
    } else {
        quote! { #builder_ident<#builder_type_args #state_chain> }
    };

    let impl_head = impl_head_with_static_bounds(generics);
    let where_clause = &generics.where_clause;
    let method_name = &method.name;
    let method_vis = &method.vis;

    // Type alias for the state chain so callers writing a specialized wrapper
    // can spell out the return type without repeating the nested `Set<…>` chain.
    // Visibility matches the method's visibility. Prefixed with `{Struct}` so
    // two `#[from_metadata]` invocations in the same module can coexist.
    let alias_ident = format_ident!(
        "{}{}State",
        struct_ident,
        pascal_case(&method_name.to_string()),
    );
    let state_alias_doc = format!(" State of [`{builder_ident}`] returned by [`{method_name}`].");
    let method_doc = format!(" Returns a [`{builder_ident}`] pre-populated from server metadata.");

    // A gated method returns `Result`, which is itself `#[must_use]` — adding
    // the attribute would trip `clippy::double_must_use` — and needs an
    // `# Errors` section for `clippy::missing_errors_doc`.
    let (must_use, errors_doc) = match gate {
        Some(gate) => {
            let field = gate_field_name(gate);
            let doc = format!(" # Errors\n\n Returns an error if the metadata has no `{field}`.");
            (quote! {}, quote! { #[doc = ""] #[doc = #doc] })
        }
        None => (quote! { #[must_use] }, quote! {}),
    };

    Ok(quote! {
        #[doc = #state_alias_doc]
        #method_vis type #alias_ident = #state_chain;

        #impl_head #struct_ident<#self_type_args> #where_clause {
            #[doc = #method_doc]
            #errors_doc
            #must_use
            #method_vis fn #method_name(
                #metadata_var: &#metadata_type,
            ) -> #return_ty {
                #body
            }
        }
    })
}

/// The metadata field a gate draws from, as it appears in the discovery
/// document: the dotted path with `?` markers stripped. A `with =` gate has no
/// path to render, so it falls back to the target field's own name.
fn gate_field_name(gate: &MetadataField) -> String {
    match &gate.extraction {
        Extraction::Path(segs) => segs
            .iter()
            .map(|s| s.name.to_string())
            .collect::<Vec<_>>()
            .join("."),
        Extraction::With { .. } => gate.field_ident.to_string(),
    }
}

fn find_fn_new_mut(item: &mut ItemImpl) -> Result<&mut syn::ImplItemFn> {
    item.items
        .iter_mut()
        .filter_map(|i| if let ImplItem::Fn(f) = i { Some(f) } else { None })
        .find(|f| f.sig.ident == "new")
        .ok_or_else(|| {
            syn::Error::new_spanned(
                &item.self_ty,
                "#[from_metadata] on an impl block requires a `fn new` (the bon-annotated constructor)",
            )
        })
}

struct MetadataField {
    field_ident: Ident,
    /// `true` if the field type is `Option<…>`.
    field_optional: bool,
    /// `true` if the field's bon setter is a fallible `with` closure
    /// (`#[builder(with = |…| -> Result<…> { … })]`), so calling it yields a
    /// `Result` that the generated code must unwrap.
    fallible_setter: bool,
    extraction: Extraction,
}

enum Extraction {
    Path(Vec<MetaPathSegment>),
    With {
        closure: ExprClosure,
        /// `true` if the closure yields `Option<T>` (user wrote `maybe`).
        yields_option: bool,
    },
}

struct MetaPathSegment {
    name: Ident,
    /// `true` if the segment was written with a trailing `?` (the segment's
    /// own type is `Option<…>` in the metadata struct).
    optional: bool,
}

impl MetadataField {
    fn from_field(field: &mut Field) -> Result<Option<Self>> {
        let Some(extraction) = take_from_metadata_attr(&mut field.attrs)? else {
            return Ok(None);
        };
        let fallible_setter = crate::util::has_fallible_with(&field.attrs)?;
        let field_ident = field.ident.clone().expect("named field");
        deny_raw_ident(&field_ident, "from_metadata")?;
        let field_optional = is_option_type(&field.ty);
        Ok(Some(Self {
            field_ident,
            field_optional,
            fallible_setter,
            extraction,
        }))
    }

    fn from_fn_arg(arg: &mut PatType) -> Result<Option<Self>> {
        let Some(extraction) = take_from_metadata_attr(&mut arg.attrs)? else {
            return Ok(None);
        };
        let fallible_setter = crate::util::has_fallible_with(&arg.attrs)?;
        let arg_ident = match &*arg.pat {
            Pat::Ident(pi) => pi.ident.clone(),
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "#[from_metadata] requires a plain `name: Type` argument",
                ));
            }
        };
        deny_raw_ident(&arg_ident, "from_metadata")?;
        let field_optional = is_option_type(&arg.ty);
        Ok(Some(Self {
            field_ident: arg_ident,
            field_optional,
            fallible_setter,
            extraction,
        }))
    }

    /// `true` when the extraction yields `Option<T>` but the grant field is
    /// `T` (not `Option<T>`) — forces an unwrap, returning `Option<Builder>`.
    fn is_gate(&self) -> bool {
        !self.field_optional && self.extraction_yields_option()
    }

    fn extraction_yields_option(&self) -> bool {
        match &self.extraction {
            Extraction::Path(segs) => segs.iter().any(|s| s.optional),
            // With escape hatch: opt-in via the `maybe` flag. Default `false`
            // matches bon's non-`maybe_` setter (which takes `T` and wraps the
            // value in `Some` for `Option<T>` fields).
            Extraction::With { yields_option, .. } => *yields_option,
        }
    }
}

/// Removes the first `#[from_metadata(...)]` attribute from `attrs` and parses
/// it. Returns `None` if no such attribute is present.
fn take_from_metadata_attr(attrs: &mut Vec<Attribute>) -> Result<Option<Extraction>> {
    let idx = attrs
        .iter()
        .position(|a| a.path().is_ident("from_metadata"));
    let Some(idx) = idx else { return Ok(None) };
    let attr = attrs.remove(idx);
    parse_extraction(&attr).map(Some)
}

fn parse_extraction(attr: &Attribute) -> Result<Extraction> {
    let mut path: Option<(String, proc_macro2::Span)> = None;
    let mut with: Option<ExprClosure> = None;
    let mut maybe = false;

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("path") {
            let value = meta.value()?;
            let lit: syn::LitStr = value.parse()?;
            path = Some((lit.value(), lit.span()));
            Ok(())
        } else if meta.path.is_ident("with") {
            let value = meta.value()?;
            let expr: Expr = value.parse()?;
            let Expr::Closure(closure) = expr else {
                return Err(meta.error("#[from_metadata(with = …)] expects a closure expression"));
            };
            if closure.inputs.len() != 1 {
                return Err(meta.error(
                    "#[from_metadata(with = …)] closure must take exactly one argument (the metadata reference)",
                ));
            }
            with = Some(closure);
            Ok(())
        } else if meta.path.is_ident("maybe") {
            maybe = true;
            Ok(())
        } else {
            Err(meta.error(
                "#[from_metadata] supports `path = \"…\"`, `with = |m| …`, or `maybe` (with `with`)",
            ))
        }
    })?;

    match (path, with, maybe) {
        (Some((p, span)), None, false) => Ok(Extraction::Path(parse_path_segments(&p, span)?)),
        (Some(_), None, true) => Err(syn::Error::new_spanned(
            attr,
            "`maybe` only applies to `with = |m| …`; use `path = \"…?\"` to mark Option segments",
        )),
        (None, Some(closure), yields_option) => Ok(Extraction::With {
            closure,
            yields_option,
        }),
        (Some(_), Some(_), _) => Err(syn::Error::new_spanned(
            attr,
            "#[from_metadata] takes either `path` or `with`, not both",
        )),
        (None, None, _) => Err(syn::Error::new_spanned(
            attr,
            "#[from_metadata] requires either `path = \"…\"` or `with = |m| …`",
        )),
    }
}

fn parse_path_segments(path: &str, span: proc_macro2::Span) -> Result<Vec<MetaPathSegment>> {
    if path.is_empty() {
        return Err(syn::Error::new(span, "path must be non-empty"));
    }
    let mut segs = Vec::new();
    for raw in path.split('.') {
        let (name, optional) = if let Some(stripped) = raw.strip_suffix('?') {
            (stripped, true)
        } else {
            (raw, false)
        };
        if name.is_empty() {
            return Err(syn::Error::new(
                span,
                format!("empty segment in path {path:?}"),
            ));
        }
        if !is_valid_ident(name) {
            return Err(syn::Error::new(
                span,
                format!("segment {name:?} is not a valid Rust identifier"),
            ));
        }
        // Shape-valid but not parseable as an identifier: a Rust keyword
        // (`type`, `self`, …) or the reserved `_`. `Ident::new` accepts
        // keywords, so without this check the generated `metadata.type`
        // field access would fail to compile with a diagnostic pointing at
        // generated code (and `_` would panic the macro). Like the
        // field-name side (`deny_raw_ident`), keyword-named (raw-identifier)
        // metadata fields are not supported.
        if syn::parse_str::<Ident>(name).is_err() {
            return Err(syn::Error::new(
                span,
                format!(
                    "segment {name:?} is a Rust keyword; #[from_metadata] does not support \
                     keyword-named (raw-identifier) metadata fields"
                ),
            ));
        }
        segs.push(MetaPathSegment {
            name: Ident::new(name, span),
            optional,
        });
    }
    Ok(segs)
}

fn is_valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        None => false,
        Some(c) if !(c.is_ascii_alphabetic() || c == '_') => false,
        _ => chars.all(|c| c.is_ascii_alphanumeric() || c == '_'),
    }
}

/// Build the chain `metadata.a.as_ref().and_then(|a| a.b.clone())` etc.
/// Returns the expression and whether it yields `Option<T>` overall.
fn path_expr(metadata_var: &Ident, segs: &[MetaPathSegment]) -> TokenStream {
    fn inner(prefix: TokenStream, segs: &[MetaPathSegment]) -> TokenStream {
        match segs {
            [] => unreachable!(),
            [last] => {
                let name = &last.name;
                quote! { #prefix.#name.clone() }
            }
            [first, rest @ ..] => {
                let name = &first.name;
                if first.optional {
                    let bind = Ident::new("__inner", name.span());
                    let inner_expr = inner(quote! { #bind }, rest);
                    let rest_yields_option = rest.iter().any(|s| s.optional);
                    if rest_yields_option {
                        quote! { #prefix.#name.as_ref().and_then(|#bind| #inner_expr) }
                    } else {
                        quote! { #prefix.#name.as_ref().map(|#bind| #inner_expr) }
                    }
                } else {
                    inner(quote! { #prefix.#name }, rest)
                }
            }
        }
    }
    inner(quote! { #metadata_var }, segs)
}

/// For a gate field, the outer expression must yield an `Option<T>` to gate on.
/// For a single-segment optional path (`field?`), this is just `metadata.field`
/// (an `Option<T>` itself). For a nested path, we still need a navigable
/// `Option<T>`. We use the full path expression here — it returns `Option<T>`
/// either way.
fn path_root_for_gate(metadata_var: &Ident, segs: &[MetaPathSegment]) -> TokenStream {
    // Special case: single optional segment → just `metadata.field` (avoids
    // a redundant `.as_ref().map(|f| f.clone()).as_ref()`).
    if let [only] = segs
        && only.optional
    {
        let name = &only.name;
        return quote! { #metadata_var.#name };
    }
    path_expr(metadata_var, segs)
}

fn build_setter_chain(
    metadata_var: &Ident,
    fields: &[MetadataField],
    gate: Option<&MetadataField>,
) -> TokenStream {
    let mut chain = TokenStream::new();
    for f in fields {
        let is_gate = gate.is_some_and(|g| g.field_ident == f.field_ident);
        let extract = if is_gate {
            // Gating field: the unwrapped value was bound by `emit_impl` to
            // the collision-proof `__huskarl_gate` local.
            let gate_var = Ident::new("__huskarl_gate", f.field_ident.span());
            quote! { #gate_var.clone() }
        } else {
            match &f.extraction {
                Extraction::Path(segs) => path_expr(metadata_var, segs),
                Extraction::With { closure, .. } => quote! { (#closure)(#metadata_var) },
            }
        };

        let setter = setter_name(f, is_gate);
        if f.fallible_setter {
            // The setter is a fallible `with` closure, so it returns
            // `Result<Builder, _>`. Metadata fields already have the target
            // type and the identity conversion is infallible, so unwrap.
            let msg = format!(
                "metadata-sourced `{}` must convert infallibly",
                f.field_ident
            );
            chain.extend(quote! { .#setter(#extract).expect(#msg) });
        } else {
            chain.extend(quote! { .#setter(#extract) });
        }
    }
    chain
}

/// Pick the bon setter to call for a field.
///
/// - `is_gate`: the value is already unwrapped (local variable form).
/// - `maybe_*` form is used when the extraction yields `Option<T>` AND the
///   grant field is `Option<T>`.
fn setter_name(f: &MetadataField, is_gate: bool) -> Ident {
    let base = f.field_ident.to_string();
    let yields_option = !is_gate && f.extraction_yields_option();
    let use_maybe = yields_option && f.field_optional;

    let name = if use_maybe {
        format!("maybe_{base}")
    } else {
        base
    };
    Ident::new(&name, f.field_ident.span())
}

fn build_state_chain(state_mod: &Ident, fields: &[MetadataField]) -> TokenStream {
    // Innermost (first call) → outermost (last call). Fields are pre-sorted
    // by name in `expand`, so this chain is stable across struct reorderings.
    let mut acc: TokenStream = quote! { #state_mod::Empty };
    for f in fields {
        let pascal = pascal_case(&f.field_ident.to_string());
        let setter_state = format_ident!("Set{}", pascal);
        acc = quote! { #state_mod::#setter_state<#acc> };
    }
    acc
}

/// `impl<…>` head for the generated `builder_from_metadata` method.
///
/// Adds `+ 'static` to every type parameter — bon's generated state-module
/// requires its type params to be `'static`, and `builder_from_metadata`
/// returns a `Builder<…>` parameterized on them. The caller is responsible
/// for splicing the struct's `where` clause after `Struct<…>`.
fn impl_head_with_static_bounds(generics: &syn::Generics) -> TokenStream {
    let mut params: Punctuated<TokenStream, Token![,]> = Punctuated::new();
    for p in &generics.params {
        match p {
            GenericParam::Type(tp) => {
                let ident = &tp.ident;
                let bounds = &tp.bounds;
                if bounds.is_empty() {
                    params.push(quote! { #ident: 'static });
                } else {
                    params.push(quote! { #ident: #bounds + 'static });
                }
            }
            GenericParam::Lifetime(lp) => {
                let lt = &lp.lifetime;
                params.push(quote! { #lt });
            }
            GenericParam::Const(cp) => {
                let ident = &cp.ident;
                let ty = &cp.ty;
                params.push(quote! { const #ident: #ty });
            }
        }
    }
    quote! { impl<#params> }
}
