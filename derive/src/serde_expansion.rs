// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redacted serde implementation generation.

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
    internal::NamedField,
};

/// Generates optional redacted serialization for parsed named fields.
///
/// # Parameters
///
/// * `input` - Derive input whose name and generics are preserved.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved direct serde dependency when integration is enabled.
/// * `container_attributes` - Validated container serde controls.
/// * `fields` - Parsed named fields in source order.
///
/// # Returns
///
/// A `RedactSerialize` implementation when serde integration is enabled, or
/// an empty token stream otherwise.
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
    serde: Option<&Path>,
    container_attributes: &ContainerAttributes,
    fields: &[NamedField<'_>],
) -> TokenStream {
    let Some(serde) = serde else {
        return TokenStream::new();
    };

    let name = &input.ident;
    let serialization_assertions = fields.iter().map(|parsed| {
        field_assertion::serialization(
            name,
            parsed.field(),
            parsed.identifier(),
            parsed.attributes().mode(),
            runtime,
        )
    });
    let serialized_fields = fields
        .iter()
        .filter_map(|parsed| {
            let field = parsed.field();
            let identifier = parsed.identifier();
            let attributes = parsed.attributes();
            let serde_attributes = parsed.serde_attributes();
            if matches!(attributes.mode(), FieldMode::Skip) || serde_attributes.skip() {
                return None;
            }
            let raw_name = identifier.to_string();
            let raw_name = raw_name.strip_prefix("r#").unwrap_or(&raw_name);
            let serialized_name = serde_attributes.rename().map_or_else(
                || container_attributes.rename_field(raw_name),
                str::to_owned,
            );
            let condition = serde_attributes.skip_serializing_if().map_or_else(
                || quote!(true),
                |predicate| quote_spanned!(field.span()=> !(#predicate)(&self.#identifier)),
            );
            let value = match attributes.mode() {
                FieldMode::Plain => {
                    quote_spanned!(field.span()=> &self.#identifier)
                }
                FieldMode::Level(sensitivity) => {
                    let level = sensitivity.runtime_tokens(runtime);
                    quote_spanned! {field.span()=>
                        &#runtime::RedactValue::redact_value(
                            &self.#identifier,
                            #level,
                            policy.masking(),
                        )
                    }
                }
                FieldMode::Nested => {
                    let helper =
                        field_assertion::helper_name(name, field, identifier, "RedactSerialize");
                    quote_spanned! {field.span()=>
                        &#helper(&self.#identifier, policy)
                    }
                }
                FieldMode::Map => {
                    let helper =
                        field_assertion::helper_name(name, field, identifier, "RedactMapSerialize");
                    quote_spanned! {field.span()=>
                        &#helper(&self.#identifier, policy)
                    }
                }
                FieldMode::Skip => return None,
            };
            Some((condition, serialized_name, value))
        })
        .collect::<Vec<_>>();
    let count_conditions =
        serialized_fields.iter().map(|(condition, _, _)| condition);
    let serialize_calls =
        serialized_fields
            .iter()
            .map(|(condition, serialized_name, value)| {
                quote! {
                    if #condition {
                        #serde::ser::SerializeStruct::serialize_field(
                            &mut state,
                            #serialized_name,
                            #value,
                        )?;
                    }
                }
            });
    let (impl_generics, type_generics, where_clause) =
        input.generics.split_for_impl();

    quote! {
        #runtime::__qubit_redact_serde! {
            impl #impl_generics #runtime::__private::RedactSerialize
                for #name #type_generics #where_clause
            {
                fn serialize_redacted<__QubitRedactSerializer>(
                    &self,
                    policy: &#runtime::RedactionPolicy,
                    serializer: __QubitRedactSerializer,
                ) -> ::core::result::Result<
                    __QubitRedactSerializer::Ok,
                    __QubitRedactSerializer::Error,
                >
                where
                    __QubitRedactSerializer:
                        #serde::Serializer,
                {
                    #(#serialization_assertions)*
                    let mut field_count = 0usize;
                    #(
                        if #count_conditions {
                            field_count += 1;
                        }
                    )*
                    let mut state =
                        #serde::Serializer::serialize_struct(
                            serializer,
                            stringify!(#name),
                            field_count,
                        )?;
                    #(#serialize_calls)*
                    #serde::ser::SerializeStruct::end(state)
                }
            }
        }
    }
}
