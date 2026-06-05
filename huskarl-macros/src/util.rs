//! Shared helpers used by `try_builder` and `from_metadata`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Attribute, GenericParam, Ident, Lit, Meta, PathArguments, Result, Token, Type, parse::Parser,
    punctuated::Punctuated,
};

/// Rejects raw identifiers (`r#type`): the derived names we generate from a
/// field name (`Set{Pascal}`, `{name}_internal`, `maybe_{name}`) are not
/// representable for raw identifiers, and `Ident::new` would panic on them.
pub(crate) fn deny_raw_ident(ident: &Ident, macro_name: &str) -> Result<()> {
    if ident.to_string().starts_with("r#") {
        return Err(syn::Error::new(
            ident.span(),
            format!("#[{macro_name}] does not support raw identifiers; rename the field"),
        ));
    }
    Ok(())
}

/// Re-emits `input` with the named helper attributes stripped from struct
/// fields and `fn` arguments.
///
/// Used on macro error paths: emitting the (cleaned) item alongside the
/// `compile_error!` keeps the type in existence, so the user sees one
/// diagnostic instead of a cascade of "cannot find type" errors at every
/// use site. Only the failing macro's own helper attributes are stripped —
/// the other macro's attributes are left for it to consume normally.
/// Returns nothing if `input` does not parse as an item — the compiler will
/// report the syntax error itself.
pub(crate) fn strip_helper_attrs_and_reemit(
    input: TokenStream,
    helper_attrs: &[&str],
) -> TokenStream {
    let Ok(mut item) = syn::parse2::<syn::Item>(input) else {
        return TokenStream::new();
    };

    let strip = |attrs: &mut Vec<Attribute>| {
        attrs.retain(|a| !helper_attrs.iter().any(|name| a.path().is_ident(name)));
    };

    match &mut item {
        syn::Item::Struct(s) => {
            for field in s.fields.iter_mut() {
                strip(&mut field.attrs);
            }
        }
        syn::Item::Impl(i) => {
            for impl_item in i.items.iter_mut() {
                if let syn::ImplItem::Fn(f) = impl_item {
                    for arg in f.sig.inputs.iter_mut() {
                        if let syn::FnArg::Typed(typed) = arg {
                            strip(&mut typed.attrs);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    quote! { #item }
}

/// Returns true if `ty` is `Option<T>` (any path whose last segment is `Option`).
pub(crate) fn is_option_type(ty: &Type) -> bool {
    let Type::Path(tp) = ty else { return false };
    tp.path
        .segments
        .last()
        .is_some_and(|seg| seg.ident == "Option")
}

/// `snake_case_word_boundaries` → `SnakeCaseWordBoundaries` (PascalCase).
pub(crate) fn pascal_case(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().chain(chars).collect(),
            }
        })
        .collect()
}

/// `FooBarBaz` → `foo_bar_baz`. Matches bon's `RenameRule::SnakeCase` for the
/// simple-PascalCase inputs we care about (consecutive uppercase letters like
/// `XMLHttpRequest` would diverge — bon yields `x_m_l_http_request`, this fn
/// yields the same, fine in practice but noted here).
pub(crate) fn pascal_to_snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && c.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// Extracts the bare ident and the literal type arguments from an impl block's
/// `Self` type. Used by impl-mode macros so the generated `impl … {Struct}<…>`
/// matches what the user wrote (e.g. `impl<T> Foo<u32, T>` → ident `Foo`,
/// args `u32, T,`) — independent of how the impl's own generic parameters are
/// named or ordered.
pub(crate) fn split_self_type(ty: &Type, macro_name: &str) -> Result<(Ident, TokenStream)> {
    if let Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
    {
        let ident = seg.ident.clone();
        let type_args = match &seg.arguments {
            PathArguments::None => quote! {},
            PathArguments::AngleBracketed(args) => {
                let inner = &args.args;
                quote! { #inner, }
            }
            PathArguments::Parenthesized(_) => {
                return Err(syn::Error::new_spanned(
                    ty,
                    format!(
                        "#[{macro_name}] on an impl block does not support `Fn(…) -> _`-style Self"
                    ),
                ));
            }
        };
        return Ok((ident, type_args));
    }
    Err(syn::Error::new_spanned(
        ty,
        format!("#[{macro_name}] on an impl block requires `Self` to be a simple path type"),
    ))
}

/// Splits a struct's generics into `(impl_params_with_bounds, type_args)`, both
/// with a trailing comma so they can be spliced before `S: builder::State`.
pub(crate) fn split_generics(generics: &syn::Generics) -> (TokenStream, TokenStream) {
    let mut impl_params: Punctuated<TokenStream, Token![,]> = Punctuated::new();
    let mut type_args: Punctuated<TokenStream, Token![,]> = Punctuated::new();

    for param in &generics.params {
        match param {
            GenericParam::Type(tp) => {
                let ident = &tp.ident;
                let bounds = &tp.bounds;
                if bounds.is_empty() {
                    impl_params.push(quote! { #ident });
                } else {
                    impl_params.push(quote! { #ident: #bounds });
                }
                type_args.push(quote! { #ident });
            }
            GenericParam::Lifetime(lp) => {
                let lt = &lp.lifetime;
                let bounds = &lp.bounds;
                if bounds.is_empty() {
                    impl_params.push(quote! { #lt });
                } else {
                    impl_params.push(quote! { #lt: #bounds });
                }
                type_args.push(quote! { #lt });
            }
            GenericParam::Const(cp) => {
                let ident = &cp.ident;
                let ty = &cp.ty;
                impl_params.push(quote! { const #ident: #ty });
                type_args.push(quote! { #ident });
            }
        }
    }

    let impl_tokens = if impl_params.is_empty() {
        quote! {}
    } else {
        quote! { #impl_params, }
    };
    let type_tokens = if type_args.is_empty() {
        quote! {}
    } else {
        quote! { #type_args, }
    };
    (impl_tokens, type_tokens)
}

/// Returns the state-module identifier the user configured on the struct via
/// `#[builder(state_mod(name = "…"))]`, or bon's default
/// (`snake_case({StructName}Builder)`) when no override is present.
///
/// We're reading bon's own attribute as the single source of truth — there's
/// no parallel knob on our side, so nothing to keep in sync.
pub(crate) fn state_mod_ident(struct_ident: &Ident, attrs: &[Attribute]) -> Result<Ident> {
    if let Some(ident) = find_builder_sub_arg(attrs, "state_mod", "name")? {
        return Ok(ident);
    }
    // Bon's default: snake_case of the builder type name `{Struct}Builder`.
    let snake = pascal_to_snake_case(&format!("{struct_ident}Builder"));
    Ok(Ident::new(&snake, struct_ident.span()))
}

/// Returns the user-configured entry-function name from
/// `#[builder(start_fn(name = "…"))]`, or bon's default of `builder`.
pub(crate) fn start_fn_ident(attrs: &[Attribute]) -> Result<Ident> {
    Ok(find_builder_sub_arg(attrs, "start_fn", "name")?
        .unwrap_or_else(|| Ident::new("builder", proc_macro2::Span::call_site())))
}

/// Walks `#[builder(...)]` looking for `<sub>(<key> = "<lit>")`. Uses
/// `Punctuated<Meta, ','>` rather than `parse_nested_meta` so we can skip
/// unrelated sub-attributes (`start_fn`, `on`, `generics`, …) without having
/// to consume their inner tokens.
///
/// A `#[builder(...)]` attribute (or `<sub>(...)` list) that fails to parse is
/// an error rather than a silent skip: missing a configured name here would
/// make the generated code reference a state module or start-fn that does not
/// exist, with a far more confusing diagnostic.
fn find_builder_sub_arg(attrs: &[Attribute], sub: &str, key: &str) -> Result<Option<Ident>> {
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    for attr in attrs {
        if !attr.path().is_ident("builder") {
            continue;
        }
        let outer = attr.parse_args_with(parser).map_err(|e| {
            syn::Error::new(
                e.span(),
                format!("could not parse this #[builder(...)] attribute (while looking for `{sub}({key} = \"…\")`): {e}"),
            )
        })?;
        for item in outer {
            let Meta::List(ml) = item else { continue };
            if !ml.path.is_ident(sub) {
                continue;
            }
            let inner = parser.parse2(ml.tokens.clone()).map_err(|e| {
                syn::Error::new(
                    e.span(),
                    format!("could not parse `{sub}(...)` inside #[builder(...)]: {e}"),
                )
            })?;
            for entry in inner {
                let Meta::NameValue(nv) = entry else { continue };
                if !nv.path.is_ident(key) {
                    continue;
                }
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: Lit::Str(s), ..
                }) = nv.value
                {
                    let mut ident: Ident = syn::parse_str(&s.value()).map_err(|_| {
                        syn::Error::new(
                            s.span(),
                            format!("`{sub}({key} = ...)` is not a valid identifier"),
                        )
                    })?;
                    ident.set_span(s.span());
                    return Ok(Some(ident));
                }
            }
        }
    }
    Ok(None)
}
