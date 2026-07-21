// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable `Redact` implementation generation.

use proc_macro2::TokenStream;
use quote::{
    quote,
    quote_spanned,
};
use syn::{
    DeriveInput,
    Path,
    spanned::Spanned,
};

use crate::{
    container_attributes::ContainerAttributes,
    field_assertion,
    field_mode::FieldMode,
    named_fields,
    serde_expansion,
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
/// Generated immutable redaction and optional serde implementation tokens.
///
/// # Errors
///
/// Returns a targeted syntax error when container or field controls are
/// invalid, or when `input` is not a named-field struct.
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
) -> syn::Result<TokenStream> {
    let container_attributes = ContainerAttributes::parse(input)?;
    let fields = named_fields::parse(
        input,
        "Redact",
        container_attributes.serde_enabled(),
    )?;
    let name = &input.ident;
    let field_calls = fields
        .iter()
        .map(|parsed| {
            let field = parsed.field();
            let identifier = parsed.identifier();
            let attributes = parsed.attributes();
            let field_name = identifier.to_string();
            let helper = field_assertion::helper_name(
                name,
                field,
                identifier,
                match attributes.mode() {
                    FieldMode::Level(_) => "RedactValue",
                    FieldMode::Nested => "Redact",
                    FieldMode::Map => "RedactMapValue",
                    FieldMode::Plain | FieldMode::Skip => "Unused",
                },
            );
            match attributes.mode() {
                FieldMode::Plain => quote_spanned! {field.span()=>
                    .field(#field_name, &self.#identifier)
                },
                FieldMode::Level(_) => {
                    quote_spanned! {field.span()=>
                        .field(
                            #field_name,
                            &#helper(&self.#identifier, policy),
                        )
                    }
                }
                FieldMode::Skip => TokenStream::new(),
                FieldMode::Nested => quote_spanned! {field.span()=>
                    .field(
                        #field_name,
                        &#helper(&self.#identifier, policy),
                    )
                },
                FieldMode::Map => quote_spanned! {field.span()=>
                    .field(
                        #field_name,
                        &#helper(&self.#identifier, policy),
                    )
                },
            }
        })
        .collect::<Vec<_>>();
    let immutable_assertions = fields
        .iter()
        .map(|parsed| {
            field_assertion::immutable(
                name,
                parsed.field(),
                parsed.identifier(),
                parsed.attributes().mode(),
                runtime,
            )
        })
        .collect::<Vec<_>>();
    let serde_impl =
        serde_expansion::expand(input, runtime, &container_attributes, &fields);
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
                #(#immutable_assertions)*
                formatter
                    .debug_struct(stringify!(#name))
                    #(#field_calls)*
                    .finish()
            }
        }
        #serde_impl
    })
}
