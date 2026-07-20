// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Named-struct validation and code generation for `Redact`.

use proc_macro2::TokenStream;
use quote::{
    quote,
    quote_spanned,
};
use syn::{
    Data,
    DeriveInput,
    Fields,
    Path,
    spanned::Spanned,
};

use crate::{
    container_attributes::ContainerAttributes,
    field_attributes::FieldAttributes,
    field_mode::FieldMode,
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
    let _container_attributes = ContainerAttributes::parse(input)?;
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

    let parsed_fields = fields
        .named
        .iter()
        .map(|field| {
            let identifier = field.ident.as_ref().ok_or_else(|| {
                syn::Error::new_spanned(
                    field,
                    "Redact requires every field to have a name",
                )
            })?;
            let attributes =
                FieldAttributes::parse(field, &input.ident, identifier)?;
            Ok((field, identifier, attributes))
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let field_calls = parsed_fields
        .iter()
        .map(|(field, identifier, attributes)| {
            let field_name = identifier.to_string();
            match attributes.mode() {
                FieldMode::Plain => quote_spanned! {field.span()=>
                    .field(#field_name, &self.#identifier)
                },
                FieldMode::Level(sensitivity) => {
                    let level = sensitivity.runtime_tokens(runtime);
                    quote_spanned! {field.span()=>
                        .field(
                            #field_name,
                            &#runtime::RedactValue::redact_value(
                                &self.#identifier,
                                #level,
                                policy.masking(),
                            ),
                        )
                    }
                }
                FieldMode::Skip => TokenStream::new(),
                FieldMode::Nested => quote_spanned! {field.span()=>
                    .field(
                        #field_name,
                        &#runtime::Redact::redacted_with(&self.#identifier, policy),
                    )
                },
                FieldMode::Map => quote_spanned! {field.span()=>
                    .field(
                        #field_name,
                        &#runtime::RedactedMap::new(&self.#identifier, policy.clone()),
                    )
                },
            }
        })
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
                    #(#field_calls)*
                    .finish()
            }
        }
    })
}
