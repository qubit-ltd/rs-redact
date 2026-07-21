// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable `RedactMut` implementation generation.

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
};

/// Expands a named-field struct into its runtime `RedactMut` implementation.
///
/// # Parameters
///
/// * `input` - Parsed derive input whose generics and fields are preserved.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
///
/// # Returns
///
/// Generated destructive redaction implementation tokens.
///
/// # Errors
///
/// Returns a targeted syntax error when container or field controls are
/// invalid, or when `input` is not a named-field struct.
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
) -> syn::Result<TokenStream> {
    ContainerAttributes::parse(input)?;
    let fields = named_fields::parse(input, "RedactMut", false)?;
    let mutations = fields
        .iter()
        .map(|parsed| {
            let field = parsed.field();
            let identifier = parsed.identifier();
            let attributes = parsed.attributes();
            let helper = field_assertion::helper_name(
                &input.ident,
                field,
                identifier,
                match attributes.mode() {
                    FieldMode::Level(_) => "RedactValueMut",
                    FieldMode::Nested => "RedactMut",
                    FieldMode::Map => "RedactMapValueMut",
                    FieldMode::Plain | FieldMode::Skip => "Unused",
                },
            );
            match attributes.mode() {
                FieldMode::Plain | FieldMode::Skip => TokenStream::new(),
                FieldMode::Level(_) => quote_spanned! {field.span()=>
                    #helper(&mut self.#identifier, policy);
                },
                FieldMode::Nested => quote_spanned! {field.span()=>
                    #helper(&mut self.#identifier, policy);
                },
                FieldMode::Map => quote_spanned! {field.span()=>
                    #helper(&mut self.#identifier, policy);
                },
            }
        })
        .collect::<Vec<_>>();
    let name = &input.ident;
    let mutable_assertions = fields
        .iter()
        .map(|parsed| {
            field_assertion::mutable(
                name,
                parsed.field(),
                parsed.identifier(),
                parsed.attributes().mode(),
                runtime,
            )
        })
        .collect::<Vec<_>>();
    let (impl_generics, type_generics, where_clause) =
        input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #runtime::RedactMut for #name #type_generics #where_clause {
            fn redact_in_place_with(&mut self, policy: &#runtime::RedactionPolicy) {
                let _ = policy;
                #(#mutable_assertions)*
                #(#mutations)*
            }
        }
    })
}
