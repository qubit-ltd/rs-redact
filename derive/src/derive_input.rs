// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Named-struct validation and code generation for `Redact`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Data,
    DeriveInput,
    Fields,
    Path,
};

/// Expands a named-field struct into its runtime `Redact` implementation.
///
/// # Parameters
///
/// * `input` - Parsed derive input whose generics and fields are preserved.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
///
/// # Returns
///
/// Generated implementation tokens for a named-field struct.
///
/// # Errors
///
/// Returns a targeted syntax error when `input` is not a named-field struct or
/// a named field unexpectedly has no identifier.
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
) -> syn::Result<TokenStream> {
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => fields,
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    "Redact can only be derived for structs with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "Redact can only be derived for structs with named fields",
            ));
        }
    };

    let field_idents = fields
        .named
        .iter()
        .map(|field| {
            field.ident.as_ref().ok_or_else(|| {
                syn::Error::new_spanned(
                    field,
                    "Redact requires every field to have a name",
                )
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let field_names = field_idents
        .iter()
        .map(|identifier| identifier.to_string())
        .collect::<Vec<_>>();
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) =
        input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #runtime::Redact for #name #type_generics #where_clause {
            fn fmt_redacted(
                &self,
                policy: &#runtime::RedactionPolicy,
                formatter: &mut ::core::fmt::Formatter<'_>,
            ) -> ::core::fmt::Result {
                let _ = policy;
                formatter
                    .debug_struct(stringify!(#name))
                    #(.field(#field_names, &self.#field_idents))*
                    .finish()
            }
        }
    })
}
