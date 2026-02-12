use proc_macro2::TokenStream;
use quote::quote;
use std::collections::HashSet;
use syn::{ImplItem, ImplItemFn, ItemImpl, Result, parse2};

/// Names of the methods that have identical bodies in every grant's
/// `OAuth2ExchangeGrant` impl.
const COMMON_METHODS: &[&str] = &[
    "client_id",
    "issuer",
    "client_auth",
    "token_endpoint",
    "mtls_token_endpoint",
    "dpop",
    "allowed_auth_methods",
];

pub fn expand(_args: TokenStream, input: TokenStream) -> Result<TokenStream> {
    let mut item = parse2::<ItemImpl>(input)?;

    let present: HashSet<String> = item
        .items
        .iter()
        .filter_map(|i| {
            if let ImplItem::Fn(f) = i {
                Some(f.sig.ident.to_string())
            } else {
                None
            }
        })
        .collect();

    for &name in COMMON_METHODS {
        if !present.contains(name) {
            item.items.push(ImplItem::Fn(common_method(name)));
        }
    }

    Ok(quote! { #item })
}

fn common_method(name: &str) -> ImplItemFn {
    match name {
        "client_id" => syn::parse_quote! {
            fn client_id(&self) -> &str {
                &self.client_id
            }
        },
        "issuer" => syn::parse_quote! {
            fn issuer(&self) -> ::core::option::Option<&str> {
                self.issuer.as_deref()
            }
        },
        "client_auth" => syn::parse_quote! {
            fn client_auth(&self) -> &Self::ClientAuth {
                &self.client_auth
            }
        },
        "token_endpoint" => syn::parse_quote! {
            fn token_endpoint(&self) -> &crate::core::EndpointUrl {
                &self.token_endpoint
            }
        },
        "mtls_token_endpoint" => syn::parse_quote! {
            fn mtls_token_endpoint(
                &self,
            ) -> ::core::option::Option<&crate::core::EndpointUrl> {
                self.mtls_token_endpoint.as_ref()
            }
        },
        "dpop" => syn::parse_quote! {
            fn dpop(&self) -> &Self::DPoP {
                &self.dpop
            }
        },
        "allowed_auth_methods" => syn::parse_quote! {
            fn allowed_auth_methods(
                &self,
            ) -> ::core::option::Option<&[::std::string::String]> {
                self.token_endpoint_auth_methods_supported.as_deref()
            }
        },
        _ => unreachable!("unknown common method: {name}"),
    }
}
