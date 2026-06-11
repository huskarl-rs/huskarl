//! `#[try_builder]` — generates fallible setters on a bon builder.
//!
//! For each field annotated `#[try_setter(Trait::method)]`, the macro:
//!   - Strips `#[try_setter]` from the field (it isn't a real attribute).
//!   - Adds `#[builder(setters(vis = "", name = "{field}_internal"))]` so bon
//!     hides its default setter.
//!   - Emits a public setter on `{Struct}Builder` that takes any `U: Trait`,
//!     calls `Trait::method(value)?`, and forwards to the hidden bon setter.
//!
//! Generic over the trait — the same macro covers `IntoEndpointUrl`, any
//! future `IntoDuration`, `IntoSecret`, etc.
//!
//! `Option<T>` fields receive an additional `maybe_{field}` setter.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Attribute, Field, Fields, FnArg, Ident, ImplItem, Item, ItemImpl, ItemStruct, Pat, PatType,
    Path, PathSegment, Result, Token, parse_quote, parse2, punctuated::Punctuated,
};

use crate::util::{
    deny_raw_ident, is_option_type, pascal_case, split_generics, split_self_type, state_mod_ident,
};

pub fn expand(input: TokenStream) -> Result<TokenStream> {
    let item: Item = parse2(input)?;
    match item {
        Item::Struct(s) => expand_struct(s),
        Item::Impl(i) => expand_impl(i),
        other => Err(syn::Error::new_spanned(
            other,
            "#[try_builder] applies to a struct (with `#[derive(Builder)]`) or to an impl block (with `#[bon::bon]` + `#[builder]` on a `fn new`)",
        )),
    }
}

fn expand_struct(mut item: ItemStruct) -> Result<TokenStream> {
    let Fields::Named(ref mut fields) = item.fields else {
        return Err(syn::Error::new_spanned(
            &item.ident,
            "#[try_builder] requires a struct with named fields",
        ));
    };

    let mut try_setters: Vec<TrySetter> = Vec::new();
    for field in fields.named.iter_mut() {
        if let Some(ts) = TrySetter::from_field(field)? {
            try_setters.push(ts);
        }
    }

    let struct_ident = &item.ident;
    let builder_ident = format_ident!("{}Builder", struct_ident);
    let state_mod = state_mod_ident(struct_ident, &item.attrs)?;
    let (impl_generics, type_args) = split_generics(&item.generics);
    let where_clause = item.generics.where_clause.clone();

    let setters: Vec<TokenStream> = try_setters
        .iter()
        .map(|ts| {
            ts.emit(
                &builder_ident,
                &state_mod,
                &impl_generics,
                &type_args,
                where_clause.as_ref(),
            )
        })
        .collect();

    Ok(quote! {
        #item
        #(#setters)*
    })
}

/// Impl-block mode: the bon builder is derived from a function (e.g.
/// `#[bon::bon] impl Foo { #[builder] async fn new(...) -> Result<Self, _> }`).
/// `#[try_setter(...)]` annotations on function arguments are rewritten the
/// same way as struct fields, and setters are emitted on `{Self}Builder`.
fn expand_impl(mut item: ItemImpl) -> Result<TokenStream> {
    // Bon's builder follows the impl's generic parameter list (not Self's
    // literal args), so we pull the bare ident from Self for the builder name
    // and read type-args from the impl's own params.
    let (struct_ident, _) = split_self_type(&item.self_ty, "try_builder")?;
    let (impl_generics, type_args) = split_generics(&item.generics);
    let where_clause = item.generics.where_clause.clone();

    let fn_new = find_fn_new_mut(&mut item)?;

    let mut try_setters: Vec<TrySetter> = Vec::new();
    for arg in fn_new.sig.inputs.iter_mut() {
        if let FnArg::Typed(typed) = arg
            && let Some(ts) = TrySetter::from_fn_arg(typed)?
        {
            try_setters.push(ts);
        }
    }

    // For fn-mode bon, `#[builder(state_mod(...))]` is on the `fn new` itself.
    let state_mod = state_mod_ident(&struct_ident, &fn_new.attrs)?;
    let builder_ident = format_ident!("{}Builder", struct_ident);

    let setters: Vec<TokenStream> = try_setters
        .iter()
        .map(|ts| {
            ts.emit(
                &builder_ident,
                &state_mod,
                &impl_generics,
                &type_args,
                where_clause.as_ref(),
            )
        })
        .collect();

    Ok(quote! {
        #item
        #(#setters)*
    })
}

fn find_fn_new_mut(item: &mut ItemImpl) -> Result<&mut syn::ImplItemFn> {
    item.items
        .iter_mut()
        .filter_map(|i| if let ImplItem::Fn(f) = i { Some(f) } else { None })
        .find(|f| f.sig.ident == "new")
        .ok_or_else(|| {
            syn::Error::new_spanned(
                &item.self_ty,
                "#[try_builder] on an impl block requires a `fn new` (the bon-annotated constructor)",
            )
        })
}

struct TrySetter {
    field_ident: Ident,
    /// The trait path — everything in `#[try_setter(a::b::Trait::method)]`
    /// except the last path segment.
    trait_path: Path,
    /// The method name — the last segment of the attribute's path.
    method: Ident,
    /// True if the field type is `Option<T>`.
    optional: bool,
}

/// Parsed contents of a `#[try_setter(Trait::method)]` attribute, before
/// being bound to a particular field/argument.
struct TryAttrSpec {
    trait_path: Path,
    method: Ident,
}

/// Finds and removes a `#[try_setter(...)]` attribute from `attrs`, parsing it
/// into a `TryAttrSpec`. Returns `None` if no such attribute is present.
fn parse_try_setter_attr(attrs: &mut Vec<Attribute>) -> Result<Option<TryAttrSpec>> {
    let idx = attrs.iter().position(|a| a.path().is_ident("try_setter"));
    let Some(idx) = idx else { return Ok(None) };

    let attr = attrs.remove(idx);
    let path: Path = attr.parse_args()?;
    if path.segments.len() < 2 {
        return Err(syn::Error::new_spanned(
            &attr,
            "#[try_setter(...)] requires a path of the form `Trait::method`",
        ));
    }

    let mut segments_iter = path.segments.iter().cloned();
    let count = path.segments.len();
    let mut trait_segments: Punctuated<PathSegment, Token![::]> = Punctuated::new();
    for _ in 0..count - 1 {
        trait_segments.push(segments_iter.next().expect("count - 1 segments"));
    }
    let method_seg = segments_iter.next().expect("trailing segment");
    if !method_seg.arguments.is_none() {
        return Err(syn::Error::new_spanned(
            &method_seg,
            "the method segment of #[try_setter(...)] cannot carry generic arguments",
        ));
    }
    let trait_path = Path {
        leading_colon: path.leading_colon,
        segments: trait_segments,
    };
    Ok(Some(TryAttrSpec {
        trait_path,
        method: method_seg.ident,
    }))
}

/// Append `#[builder(setters(vis = "", name = "{ident}_internal"))]` so bon's
/// default setter is hidden. Works on either a field or a function argument's
/// `attrs` vec.
fn push_bon_hide(attrs: &mut Vec<Attribute>, ident: &Ident) {
    let internal_name = format!("{ident}_internal");
    let bon_hide: Attribute = parse_quote! { #[builder(setters(vis = "", name = #internal_name))] };
    attrs.push(bon_hide);
}

impl TrySetter {
    /// Reads (and removes) `#[try_setter(...)]` from `field`. If present, also
    /// injects `#[builder(setters(vis = "", name = "{field}_internal"))]` so
    /// bon hides its default setter for the field.
    fn from_field(field: &mut Field) -> Result<Option<Self>> {
        let Some(spec) = parse_try_setter_attr(&mut field.attrs)? else {
            return Ok(None);
        };
        let field_ident = field.ident.clone().expect("named field has an ident");
        deny_raw_ident(&field_ident, "try_setter")?;
        let optional = is_option_type(&field.ty);
        push_bon_hide(&mut field.attrs, &field_ident);
        Ok(Some(Self::build(field_ident, optional, spec)))
    }

    /// Impl-block mode: the same logic, on a function argument.
    fn from_fn_arg(arg: &mut PatType) -> Result<Option<Self>> {
        let Some(spec) = parse_try_setter_attr(&mut arg.attrs)? else {
            return Ok(None);
        };
        let arg_ident = match &*arg.pat {
            Pat::Ident(pi) => pi.ident.clone(),
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "#[try_setter] requires a plain `name: Type` argument",
                ));
            }
        };
        deny_raw_ident(&arg_ident, "try_setter")?;
        let optional = is_option_type(&arg.ty);
        push_bon_hide(&mut arg.attrs, &arg_ident);
        Ok(Some(Self::build(arg_ident, optional, spec)))
    }

    fn build(field_ident: Ident, optional: bool, spec: TryAttrSpec) -> Self {
        Self {
            field_ident,
            trait_path: spec.trait_path,
            method: spec.method,
            optional,
        }
    }

    fn emit(
        &self,
        builder_ident: &Ident,
        state_mod: &Ident,
        impl_generics: &TokenStream,
        type_args: &TokenStream,
        where_clause: Option<&syn::WhereClause>,
    ) -> TokenStream {
        let Self {
            field_ident,
            trait_path,
            method,
            optional,
        } = self;

        let internal = format_ident!("{}_internal", field_ident);
        let state_assoc = format_ident!("{}", pascal_case(&field_ident.to_string()));
        let state_set = format_ident!("Set{}", state_assoc);

        // Prefixed so they cannot collide with the user's own generic
        // parameters (a struct generic named `S` or `U` is perfectly legal).
        let state_param = format_ident!("__HuskarlS");
        let value_param = format_ident!("__HuskarlU");

        // Build doc strings in the macro rather than with `stringify!`:
        // stringified path tokens render with spaces between segments
        // (`crate :: core :: Trait`), which breaks the intra-doc link.
        let trait_path_str = {
            use quote::ToTokens as _;
            trait_path.to_token_stream().to_string().replace(' ', "")
        };
        let err_doc = format!(" [`{trait_path_str}`].");
        let set_doc = format!(" Sets `{field_ident}`.");

        let impl_head = quote! {
            impl<#impl_generics #state_param: #state_mod::State>
                #builder_ident<#type_args #state_param> #where_clause
        };
        let return_ty = quote! {
            ::core::result::Result<
                #builder_ident<#type_args #state_mod::#state_set<#state_param>>,
                ::huskarl_core::Error,
            >
        };

        let required_setter = quote! {
            #[doc = #set_doc]
            ///
            /// # Errors
            ///
            /// Returns an error if the value cannot be converted via
            #[doc = #err_doc]
            pub fn #field_ident<#value_param: #trait_path>(
                self,
                value: #value_param,
            ) -> #return_ty
            where
                #state_param::#state_assoc: #state_mod::IsUnset,
            {
                ::core::result::Result::Ok(self.#internal(#trait_path::#method(value)?))
            }
        };

        if !optional {
            return quote! {
                #impl_head {
                    #required_setter
                }
            };
        }

        let maybe_ident = format_ident!("maybe_{}", field_ident);
        let maybe_internal = format_ident!("maybe_{}_internal", field_ident);
        let maybe_doc = format!(" Sets `{field_ident}`, or leaves it unset when `None`.");
        let maybe_setter = quote! {
            #[doc = #maybe_doc]
            ///
            /// # Errors
            ///
            /// Returns an error if the value cannot be converted via
            #[doc = #err_doc]
            pub fn #maybe_ident<#value_param: #trait_path>(
                self,
                value: ::core::option::Option<#value_param>,
            ) -> #return_ty
            where
                #state_param::#state_assoc: #state_mod::IsUnset,
            {
                ::core::result::Result::Ok(self.#maybe_internal(
                    value.map(#trait_path::#method).transpose()?,
                ))
            }
        };

        quote! {
            #impl_head {
                #required_setter
                #maybe_setter
            }
        }
    }
}
