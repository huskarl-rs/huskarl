//! Expansion of the `Classify` derive.

use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, Type, Variant, parse_quote, spanned::Spanned as _};

/// The classification established by a leaf variant.
enum Establishes {
    /// `#[classify(no)]`: retrying will not help.
    No,
    /// `#[classify(retry)]`: the same operation may succeed later.
    Retry,
    /// `#[classify(with = path)]`: call `path` with references to the fields.
    With(syn::Path),
}

pub fn expand(input: TokenStream) -> TokenStream {
    let input: DeriveInput = match syn::parse2(input) {
        Ok(parsed) => parsed,
        Err(e) => return e.to_compile_error(),
    };
    let Data::Enum(data) = &input.data else {
        return syn::Error::new(
            input.span(),
            "`Classify` is for cause enums; a struct cause has one shape and can \
             implement `Cause` directly",
        )
        .to_compile_error();
    };

    let name = &input.ident;
    let core = huskarl_core();
    let krate = &core.path;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let mut arms = Vec::new();
    let mut errors = Vec::new();
    for variant in &data.variants {
        match variant_arm(variant, &core) {
            Ok(arm) => arms.push(arm),
            Err(e) => errors.push(e.to_compile_error()),
        }
    }
    if !errors.is_empty() {
        return quote! { #(#errors)* };
    }

    quote! {
        impl #impl_generics #krate::error::propagation::Cause for #name #ty_generics #where_clause {
            fn origin(&self) -> #krate::error::propagation::Origin<'_> {
                use #krate::error::propagation::Origin;
                match self { #(#arms)* }
            }
        }

        impl #impl_generics ::core::convert::From<#name #ty_generics> for #krate::Error #where_clause {
            #[track_caller]
            fn from(source: #name #ty_generics) -> Self {
                Self::from_cause(source)
            }
        }
    }
}

/// Builds one match arm, inferring propagation before reading the attribute.
fn variant_arm(variant: &Variant, core: &HuskarlCore) -> syn::Result<TokenStream> {
    let ident = &variant.ident;
    let declared = establishes(variant)?;
    let krate = &core.path;

    match (wrapped_field(&variant.fields, core), declared) {
        // An `Error` field already determines that this variant propagates.
        (Some(_), Some(_)) => Err(syn::Error::new(
            variant.span(),
            "this variant has a field of type `Error`, so it propagates that \
             error's classification; remove the `#[classify(...)]` attribute. To \
             override one member, use `#[classify(with = path)]` and build from \
             `Error::classification`",
        )),
        (Some(field), None) => {
            let binding = field.binding();
            let pattern = field.pattern();
            Ok(quote! { Self::#ident #pattern => Origin::Propagates(#binding), })
        }
        // Leaf variants must state the classification they establish.
        (None, None) => Err(syn::Error::new(
            variant.span(),
            "this variant wraps no classified error, so it must say what it \
             establishes: `#[classify(no)]`, `#[classify(retry)]`, or \
             `#[classify(with = path)]`",
        )),
        (None, Some(Establishes::With(path))) => with_arm(variant, path),
        (None, Some(Establishes::No)) => Ok(quote! {
            Self::#ident { .. } => Origin::Establishes(#krate::RetryAdvice::No.into()),
        }),
        (None, Some(Establishes::Retry)) => Ok(quote! {
            Self::#ident { .. } => Origin::Establishes(#krate::RetryAdvice::RETRY.into()),
        }),
    }
}

/// Builds a `with = path` arm that passes field references in declaration order.
fn with_arm(variant: &Variant, path: syn::Path) -> syn::Result<TokenStream> {
    let ident = &variant.ident;
    match &variant.fields {
        Fields::Named(fields) => {
            let bindings = fields
                .named
                .iter()
                .map(|field| field.ident.as_ref().expect("a named field has an ident"));
            let arguments = bindings.clone();
            Ok(quote! { Self::#ident { #(#bindings,)* } => #path(#(#arguments),*), })
        }
        Fields::Unnamed(fields) => {
            let bindings: Vec<_> = (0..fields.unnamed.len())
                .map(|index| Ident::new(&format!("field_{index}"), variant.span()))
                .collect();
            Ok(quote! { Self::#ident(#(#bindings),*) => #path(#(#bindings),*), })
        }
        Fields::Unit => Ok(quote! { Self::#ident => #path(), }),
    }
}

/// A named or positional field whose type is `Error`.
struct WrappedField {
    ident: Option<Ident>,
    index: usize,
    arity: usize,
    named: bool,
}

impl WrappedField {
    fn binding(&self) -> TokenStream {
        match &self.ident {
            Some(ident) => quote! { #ident },
            None => {
                let bound = Ident::new("inner", proc_macro2::Span::call_site());
                quote! { #bound }
            }
        }
    }

    fn pattern(&self) -> TokenStream {
        if self.named {
            let ident = self.ident.as_ref().expect("a named field has an ident");
            quote! { { #ident, .. } }
        } else {
            let before = (0..self.index).map(|_| quote! { _, });
            let after = (self.index + 1..self.arity).map(|_| quote! { _, });
            quote! { ( #(#before)* inner, #(#after)* ) }
        }
    }
}

/// Finds the first field that contains a recognized huskarl `Error`.
fn wrapped_field(fields: &Fields, core: &HuskarlCore) -> Option<WrappedField> {
    let arity = fields.len();
    fields.iter().enumerate().find_map(|(index, field)| {
        is_error(&field.ty, core).then(|| WrappedField {
            ident: field.ident.clone(),
            index,
            arity,
            named: field.ident.is_some(),
        })
    })
}

/// Whether this field's type is huskarl's own `Error`.
///
/// Recognizes bare `Error` and paths rooted at the resolved huskarl-core crate.
/// It deliberately does not accept arbitrary paths ending in `Error`: cause
/// enums commonly contain `std::io::Error` and other foreign error types.
fn is_error(ty: &Type, core: &HuskarlCore) -> bool {
    let Type::Path(path) = ty else { return false };
    if path.qself.is_some() {
        return false;
    }

    let segments = &path.path.segments;
    if segments.len() == 1 {
        return segments[0].ident == "Error";
    }

    segments.len() == 2
        && segments[1].ident == "Error"
        && match &core.qualifier {
            CoreQualifier::Crate => segments[0].ident == "crate",
            CoreQualifier::Dependency(name) => segments[0].ident == *name,
        }
}

/// Parses the variant's `#[classify(...)]` attribute, if present.
fn establishes(variant: &Variant) -> syn::Result<Option<Establishes>> {
    let mut found = None;
    let mut attribute_seen = false;
    for attr in &variant.attrs {
        if !attr.path().is_ident("classify") {
            continue;
        }
        if attribute_seen {
            return Err(syn::Error::new(attr.span(), "duplicate `#[classify(...)]`"));
        }
        attribute_seen = true;
        let mut parsed = None;
        attr.parse_nested_meta(|meta| {
            if parsed.is_some() {
                return Err(meta.error("multiple `classify` directives in one attribute"));
            }
            if meta.path.is_ident("no") {
                parsed = Some(Establishes::No);
            } else if meta.path.is_ident("retry") {
                parsed = Some(Establishes::Retry);
            } else if meta.path.is_ident("with") {
                parsed = Some(Establishes::With(meta.value()?.parse()?));
            } else {
                return Err(meta.error("expected `no`, `retry`, or `with = path`"));
            }
            Ok(())
        })?;
        found = parsed;
    }
    Ok(found)
}

enum CoreQualifier {
    Crate,
    Dependency(Ident),
}

struct HuskarlCore {
    path: syn::Path,
    qualifier: CoreQualifier,
}

/// Resolves huskarl-core as `crate` or by its dependency name, including aliases.
fn huskarl_core() -> HuskarlCore {
    match crate_name("huskarl-core") {
        Ok(FoundCrate::Itself) => HuskarlCore {
            path: parse_quote!(crate),
            qualifier: CoreQualifier::Crate,
        },
        Ok(FoundCrate::Name(name)) => {
            let name = Ident::new(&name, proc_macro2::Span::call_site());
            HuskarlCore {
                path: parse_quote!(::#name),
                qualifier: CoreQualifier::Dependency(name),
            }
        }
        // Let rustc report a missing dependency at the generated use site.
        Err(_) => HuskarlCore {
            path: parse_quote!(::huskarl_core),
            qualifier: CoreQualifier::Dependency(Ident::new(
                "huskarl_core",
                proc_macro2::Span::call_site(),
            )),
        },
    }
}
