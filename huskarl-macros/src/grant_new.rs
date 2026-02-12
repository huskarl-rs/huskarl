use proc_macro2::TokenStream;
use quote::quote;
use syn::{FnArg, ImplItem, ItemImpl, Pat, Result, parse2};

use crate::grant::{
    EndpointUrlField, builder_generics, common_fields, endpoint_url_setter, field_to_fn_arg,
    is_option_type, process_endpoint_url_fields, with_common_metadata_impl,
};

pub fn expand(input: TokenStream) -> Result<TokenStream> {
    let mut item = parse2::<ItemImpl>(input)?;

    // Find fn new inside the impl block.
    let fn_new = item
        .items
        .iter_mut()
        .filter_map(|i| {
            if let ImplItem::Fn(f) = i {
                Some(f)
            } else {
                None
            }
        })
        .find(|f| f.sig.ident == "new")
        .ok_or_else(|| syn::Error::new_spanned(&item.self_ty, "#[grant_new] requires a fn new"))?;

    // Process #[endpoint_url] / #[endpoint_url(optional)] on user-written params.
    let mut endpoint_url_fields: Vec<EndpointUrlField> = Vec::new();
    for arg in fn_new.sig.inputs.iter_mut() {
        if let FnArg::Typed(typed) = arg {
            let idx = typed
                .attrs
                .iter()
                .position(|a| a.path().is_ident("endpoint_url"));
            if let Some(idx) = idx {
                let doc_attrs: Vec<_> = typed
                    .attrs
                    .iter()
                    .filter(|a| a.path().is_ident("doc"))
                    .cloned()
                    .collect();
                typed.attrs.remove(idx);
                let optional = is_option_type(&typed.ty);
                let ident = match &*typed.pat {
                    Pat::Ident(pi) => pi.ident.clone(),
                    other => {
                        return Err(syn::Error::new_spanned(other, "expected ident pattern"));
                    }
                };
                let internal_name = format!("{ident}_internal");
                let builder_attr: syn::Attribute =
                    syn::parse_quote! { #[builder(setters(vis = "", name = #internal_name))] };
                typed.attrs.push(builder_attr);
                endpoint_url_fields.push(EndpointUrlField {
                    ident,
                    optional,
                    doc_attrs,
                });
            }
        }
    }

    // Prepend the common parameters (with docs) before user-written params.
    // Process #[endpoint_url] annotations on common fields so they get the same
    // IntoEndpointUrl setter treatment as user-declared endpoint URL parameters.
    let (processed_common, common_endpoint_url_fields) =
        process_endpoint_url_fields(common_fields(), true);
    endpoint_url_fields = common_endpoint_url_fields
        .into_iter()
        .chain(endpoint_url_fields)
        .collect();

    let existing: Vec<FnArg> = fn_new.sig.inputs.iter().cloned().collect();
    fn_new.sig.inputs.clear();
    for p in processed_common.into_iter().map(field_to_fn_arg) {
        fn_new.sig.inputs.push(p);
    }
    for p in existing {
        fn_new.sig.inputs.push(p);
    }

    // Derive builder name and generics from the impl block's self type and generics.
    let struct_name = extract_struct_name(&item.self_ty)?;
    let builder_name = syn::Ident::new(&format!("{}Builder", struct_name), struct_name.span());
    let (impl_params, type_args) = builder_generics(&item.generics);

    let common_metadata = with_common_metadata_impl(&builder_name, &type_args, &impl_params);
    let endpoint_url_setters: Vec<TokenStream> = endpoint_url_fields
        .iter()
        .map(|f| endpoint_url_setter(&builder_name, &type_args, &impl_params, f))
        .collect();

    Ok(quote! {
        #item
        #common_metadata
        #(#endpoint_url_setters)*
    })
}

fn extract_struct_name(ty: &syn::Type) -> Result<syn::Ident> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
    {
        return Ok(seg.ident.clone());
    }
    Err(syn::Error::new_spanned(
        ty,
        "#[grant_new]: self type must be a simple path",
    ))
}
