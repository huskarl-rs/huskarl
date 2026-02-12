use darling::{FromMeta, ast::NestedMeta};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Attribute, Field, Fields, FnArg, GenericParam, Ident, ItemStruct, Pat, PatIdent, PatType,
    Result, Visibility, parse_quote, parse2,
};

pub(crate) struct EndpointUrlField {
    pub(crate) ident: Ident,
    pub(crate) optional: bool,
    pub(crate) doc_attrs: Vec<Attribute>,
}

/// Parsed arguments for `#[grant(...)]`.
///
/// Usage: `#[grant(vis(pub(super)))]`
#[derive(Debug, Default, FromMeta)]
struct GrantArgs {
    /// Visibility of the injected common fields. Defaults to private.
    #[darling(default)]
    vis: Option<VisArg>,
}

/// Newtype for [`Visibility`] with a [`FromMeta`] impl that parses `vis(pub(super))` meta lists.
#[derive(Debug)]
struct VisArg(Visibility);

impl FromMeta for VisArg {
    fn from_meta(item: &syn::Meta) -> darling::Result<Self> {
        let syn::Meta::List(list) = item else {
            return Err(darling::Error::unexpected_type("list").with_span(item));
        };
        syn::parse2::<Visibility>(list.tokens.clone())
            .map(VisArg)
            .map_err(|e| darling::Error::custom(e.to_string()).with_span(item))
    }
}

/// Returns true if the struct has `#[derive(Builder)]` (or `#[derive(bon::Builder)]`).
///
/// When a struct uses `#[bon::bon]` + `#[builder]` on `async fn new`, the builder
/// is derived from function parameters, not struct fields.  In that case we must
/// NOT emit `#[builder(...)]` helper attributes on struct fields, since there is no
/// derive macro to consume them.
fn has_derive_builder(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        )
        .ok()
        .map(|paths| paths.iter().any(|p| p.is_ident("Builder")))
        .unwrap_or(false)
    })
}

pub fn expand(args: TokenStream, input: TokenStream) -> Result<TokenStream> {
    let attr_args = NestedMeta::parse_meta_list(args)
        .map_err(|e| syn::Error::new(proc_macro2::Span::call_site(), e.to_string()))?;
    let grant_args = GrantArgs::from_list(&attr_args)
        .map_err(|e| syn::Error::new(proc_macro2::Span::call_site(), e.to_string()))?;

    let field_vis = grant_args.vis.map(|v| v.0).unwrap_or(Visibility::Inherited);

    let mut item = parse2::<ItemStruct>(input)?;

    let Fields::Named(ref mut fields) = item.fields else {
        return Err(syn::Error::new_spanned(
            &item.ident,
            "#[grant] can only be applied to structs with named fields",
        ));
    };

    let derive_builder = has_derive_builder(&item.attrs);

    // Prepend Auth and D generics before any user-declared generics.
    let auth_param: GenericParam = parse_quote! {
        Auth: crate::core::client_auth::ClientAuthentication
    };
    let d_param: GenericParam = parse_quote! {
        D: crate::core::dpop::AuthorizationServerDPoP = crate::core::dpop::NoDPoP
    };
    let existing_params: Vec<GenericParam> = item.generics.params.iter().cloned().collect();
    item.generics.params.clear();
    item.generics.params.push(auth_param);
    item.generics.params.push(d_param);
    for p in existing_params {
        item.generics.params.push(p);
    }

    // Process common and user-declared fields, extracting #[endpoint_url] annotations.
    let existing_user_fields: Vec<Field> = fields.named.iter().cloned().collect();
    let (processed_common_fields, common_endpoint_url_fields) =
        process_endpoint_url_fields(common_fields(), derive_builder);
    let (processed_user_fields, user_endpoint_url_fields) =
        process_endpoint_url_fields(existing_user_fields, derive_builder);
    let endpoint_url_fields: Vec<EndpointUrlField> = common_endpoint_url_fields
        .into_iter()
        .chain(user_endpoint_url_fields)
        .collect();

    // Assemble fields: common first, then grant-specific.
    fields.named.clear();
    for mut f in processed_common_fields {
        // Apply the configured visibility to injected common fields.
        f.vis = field_vis.clone();
        fields.named.push(f);
    }
    for f in processed_user_fields {
        fields.named.push(f);
    }

    let struct_name = &item.ident;
    let builder_name = Ident::new(&format!("{}Builder", struct_name), struct_name.span());
    let (impl_params, type_args) = builder_generics(&item.generics);

    // In Mode 2 (no #[derive(Builder)]), setters and with_common_metadata are emitted by
    // #[grant_new] on the impl block instead, since the builder comes from `async fn new`.
    let (common_metadata, endpoint_url_setters) = if derive_builder {
        let common_metadata = with_common_metadata_impl(&builder_name, &type_args, &impl_params);
        let endpoint_url_setters: Vec<TokenStream> = endpoint_url_fields
            .iter()
            .map(|f| endpoint_url_setter(&builder_name, &type_args, &impl_params, f))
            .collect();
        (common_metadata, endpoint_url_setters)
    } else {
        (quote! {}, vec![])
    };

    Ok(quote! {
        #item
        #common_metadata
        #(#endpoint_url_setters)*
    })
}

/// Extracts `#[endpoint_url]` annotation from a list of fields.
///
/// For each annotated field:
/// - Removes the `#[endpoint_url]` attribute
/// - When `derive_builder` is true, injects a private `#[builder(setters(vis = "", name = ...))]`
///   so bon hides its default setter; the public `IntoEndpointUrl` setter is generated separately.
///
/// Returns the processed fields and the list of endpoint URL field descriptors.
pub(crate) fn process_endpoint_url_fields(
    fields: Vec<Field>,
    derive_builder: bool,
) -> (Vec<Field>, Vec<EndpointUrlField>) {
    let mut processed = Vec::new();
    let mut endpoint_url_fields = Vec::new();

    for mut field in fields {
        let idx = field
            .attrs
            .iter()
            .position(|a| a.path().is_ident("endpoint_url"));

        if let Some(idx) = idx {
            let doc_attrs: Vec<Attribute> = field
                .attrs
                .iter()
                .filter(|a| a.path().is_ident("doc"))
                .cloned()
                .collect();
            field.attrs.remove(idx);
            let optional = is_option_type(&field.ty);
            let field_ident = field.ident.clone().expect("named field");

            // When the struct uses #[derive(Builder)], hide the default bon setter
            // with a private _internal name; the macro generates the public
            // IntoEndpointUrl setter.  When there is no derive (e.g. async fn new
            // builder), the internal setter already comes from the function
            // parameter — adding #[builder] to the struct field would error.
            if derive_builder {
                let internal_name = format!("{}_internal", field_ident);
                let builder_attr: Attribute =
                    parse_quote! { #[builder(setters(vis = "", name = #internal_name))] };
                field.attrs.push(builder_attr);
            }

            endpoint_url_fields.push(EndpointUrlField {
                ident: field_ident,
                optional,
                doc_attrs,
            });
        }

        processed.push(field);
    }

    (processed, endpoint_url_fields)
}

/// Returns true if `ty` is `Option<T>` (any path ending in `Option`).
pub(crate) fn is_option_type(ty: &syn::Type) -> bool {
    let syn::Type::Path(tp) = ty else {
        return false;
    };
    tp.path
        .segments
        .last()
        .is_some_and(|seg| seg.ident == "Option")
}

/// Converts a `snake_case` identifier string to `PascalCase`.
pub(crate) fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    let upper: String = first.to_uppercase().collect();
                    upper + chars.as_str()
                }
            }
        })
        .collect()
}

/// Generates `IntoEndpointUrl` setters on the builder for a field annotated
/// with `#[endpoint_url]` or `#[endpoint_url(optional)]`.
///
/// - Required fields get `fn field_name<U: IntoEndpointUrl>(url: U) -> Result<...>`
/// - Optional fields get both `fn field_name` (sets `Some`) and `fn maybe_field_name` (sets `Option`)
pub(crate) fn endpoint_url_setter(
    builder_name: &Ident,
    type_args: &TokenStream,
    impl_params: &TokenStream,
    field: &EndpointUrlField,
) -> TokenStream {
    let field_ident = &field.ident;
    let pascal = to_pascal_case(&field_ident.to_string());
    // `Set{Pascal}` is used for the return type state; bare `{Pascal}` is the
    // associated type name in the `where` clause (bon's naming convention).
    let state_type = Ident::new(&format!("Set{pascal}"), field_ident.span());
    let assoc_type = Ident::new(&pascal, field_ident.span());

    let setter_doc = format!(" Sets `{field_ident}`.");
    let doc_attrs = &field.doc_attrs;
    let field_doc_section = if doc_attrs.is_empty() {
        quote! {}
    } else {
        quote! {
            ///
            #(#doc_attrs)*
        }
    };

    if field.optional {
        let maybe_setter = Ident::new(&format!("maybe_{field_ident}"), field_ident.span());
        // bon generates `foo_internal(T)` and `maybe_foo_internal(Option<T>)` for Option<T> fields.
        let internal_setter = Ident::new(&format!("{field_ident}_internal"), field_ident.span());
        let maybe_internal_setter =
            Ident::new(&format!("maybe_{field_ident}_internal"), field_ident.span());
        quote! {
            impl<#impl_params, S: builder::State> #builder_name<#type_args, S> {
                #[doc = #setter_doc]
                #field_doc_section
                ///
                /// Accepts any type that implements
                /// [`IntoEndpointUrl`](crate::core::IntoEndpointUrl).
                ///
                /// # Errors
                ///
                /// Returns an error if the value cannot be parsed as a valid URI.
                pub fn #field_ident<U: crate::core::IntoEndpointUrl>(
                    self,
                    url: U,
                ) -> Result<#builder_name<#type_args, builder::#state_type<S>>, U::Error>
                where
                    S::#assoc_type: builder::IsUnset,
                {
                    Ok(self.#internal_setter(url.into_endpoint_url()?))
                }

                #[doc = #setter_doc]
                #field_doc_section
                ///
                /// Accepts any type that implements
                /// [`IntoEndpointUrl`](crate::core::IntoEndpointUrl),
                /// or `None` to leave the field unset.
                ///
                /// # Errors
                ///
                /// Returns an error if the value cannot be parsed as a valid URI.
                pub fn #maybe_setter<U: crate::core::IntoEndpointUrl>(
                    self,
                    url: ::core::option::Option<U>,
                ) -> Result<#builder_name<#type_args, builder::#state_type<S>>, U::Error>
                where
                    S::#assoc_type: builder::IsUnset,
                {
                    Ok(self.#maybe_internal_setter(
                        url.map(crate::core::IntoEndpointUrl::into_endpoint_url)
                            .transpose()?,
                    ))
                }
            }
        }
    } else {
        let internal_setter = Ident::new(&format!("{field_ident}_internal"), field_ident.span());
        quote! {
            impl<#impl_params, S: builder::State> #builder_name<#type_args, S> {
                #[doc = #setter_doc]
                #field_doc_section
                ///
                /// Accepts any type that implements
                /// [`IntoEndpointUrl`](crate::core::IntoEndpointUrl).
                ///
                /// # Errors
                ///
                /// Returns an error if the value cannot be parsed as a valid URI.
                pub fn #field_ident<U: crate::core::IntoEndpointUrl>(
                    self,
                    url: U,
                ) -> Result<#builder_name<#type_args, builder::#state_type<S>>, U::Error>
                where
                    S::#assoc_type: builder::IsUnset,
                {
                    Ok(self.#internal_setter(url.into_endpoint_url()?))
                }
            }
        }
    }
}

/// The seven fields common to every grant struct.
pub(crate) fn common_fields() -> Vec<Field> {
    let s: ItemStruct = parse_quote! {
        struct _CommonGrantFields {
            /// The client ID.
            client_id: String,

            /// The client authentication method.
            client_auth: Auth,

            /// The DPoP signer.
            dpop: D,

            /// The issuer for tokens created by the authorization server.
            issuer: Option<String>,

            /// The URL of the token endpoint.
            #[endpoint_url]
            token_endpoint: crate::core::EndpointUrl,

            /// The mTLS alias for the token endpoint (RFC 8705 §5).
            #[endpoint_url]
            mtls_token_endpoint: Option<crate::core::EndpointUrl>,

            /// Supported endpoint auth methods; used to auto-select basic or
            /// form auth for client secrets.
            token_endpoint_auth_methods_supported: Option<Vec<String>>,
        }
    };

    match s.fields {
        Fields::Named(named) => named.named.into_iter().collect(),
        _ => unreachable!(),
    }
}

/// Build the generic parameter lists for `impl<...> XxxBuilder<...>`.
///
/// Returns `(impl_params, type_args)`:
/// - `impl_params`: bounds with `+ 'static` on type params
/// - `type_args`: bare idents/lifetimes (no bounds, no defaults)
pub(crate) fn builder_generics(generics: &syn::Generics) -> (TokenStream, TokenStream) {
    let mut impl_params = Vec::new();
    let mut type_args = Vec::new();

    for param in &generics.params {
        match param {
            GenericParam::Type(tp) => {
                let ident = &tp.ident;
                let bounds = &tp.bounds;
                let full_bounds = if bounds.is_empty() {
                    quote! { 'static }
                } else {
                    quote! { #bounds + 'static }
                };
                impl_params.push(quote! { #ident: #full_bounds });
                type_args.push(quote! { #ident });
            }
            GenericParam::Lifetime(lp) => {
                let lt = &lp.lifetime;
                impl_params.push(quote! { #lt });
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

    (quote! { #(#impl_params),* }, quote! { #(#type_args),* })
}

/// Generates the `with_common_metadata` method on the builder.
///
/// Sets the four fields shared by every grant that can be sourced from
/// `AuthorizationServerMetadata`: `issuer`, `token_endpoint_auth_methods_supported`,
/// `token_endpoint`, and `mtls_token_endpoint`.
pub(crate) fn with_common_metadata_impl(
    builder_name: &Ident,
    type_args: &TokenStream,
    impl_params: &TokenStream,
) -> TokenStream {
    quote! {
        /// Builder state after calling [`with_common_metadata`] on a fresh builder.
        ///
        /// The `S` parameter allows composing with prior state; defaults to
        /// [`builder::Empty`] (i.e. a freshly created builder).
        pub type SetCommonMetadata<S = builder::Empty> =
            builder::SetMtlsTokenEndpoint<
                builder::SetTokenEndpoint<
                    builder::SetTokenEndpointAuthMethodsSupported<builder::SetIssuer<S>>
                >
            >;

        impl<#impl_params, S: builder::State> #builder_name<#type_args, S>
        where
            S::Issuer: builder::IsUnset,
            S::TokenEndpointAuthMethodsSupported: builder::IsUnset,
            S::TokenEndpoint: builder::IsUnset,
            S::MtlsTokenEndpoint: builder::IsUnset,
        {
            /// Configures the common grant fields from authorization server metadata.
            ///
            /// Sets `issuer`, `token_endpoint_auth_methods_supported`, `token_endpoint`,
            /// and the mTLS token endpoint alias (when present in metadata).
            pub fn with_common_metadata(
                self,
                metadata: &crate::core::server_metadata::AuthorizationServerMetadata,
            ) -> #builder_name<#type_args, SetCommonMetadata<S>> {
                self.issuer(metadata.issuer.clone())
                    .token_endpoint_auth_methods_supported(
                        metadata.token_endpoint_auth_methods_supported.clone(),
                    )
                    .token_endpoint_internal(metadata.token_endpoint.clone())
                    .maybe_mtls_token_endpoint_internal(
                        metadata
                            .mtls_endpoint_aliases
                            .as_ref()
                            .and_then(|a| a.token_endpoint.clone()),
                    )
            }
        }
    }
}

/// Converts a named struct field into an equivalent `fn` parameter.
///
/// Attributes (including `#[builder(...)]` and doc comments) and the type are
/// preserved. Used by `#[grant_new]` to derive common `fn new` parameters
/// directly from [`common_fields`], keeping the two in sync.
pub(crate) fn field_to_fn_arg(field: Field) -> FnArg {
    let ident = field.ident.expect("named field");
    FnArg::Typed(PatType {
        attrs: field.attrs,
        pat: Box::new(Pat::Ident(PatIdent {
            attrs: vec![],
            by_ref: None,
            mutability: None,
            ident,
            subpat: None,
        })),
        colon_token: field.colon_token.unwrap(),
        ty: Box::new(field.ty),
    })
}
