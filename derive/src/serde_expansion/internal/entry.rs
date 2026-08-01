// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Entry point and capability assertions for redacted Serde expansion.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Path};

use crate::{
    field_assertion,
    internal::{ContainerData, FieldsData},
    serde_container_attributes::SerdeContainerAttributes,
};

use super::{
    enum_expansion::enum_body, field_serialization::field_context, struct_expansion::struct_body,
};

/// Generates optional redacted serialization for every supported input shape.
///
/// # Parameters
///
/// * `input` - Derive input whose name and generics are preserved.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved direct Serde dependency when integration is enabled.
/// * `container_attributes` - Validated Serde container controls.
/// * `model` - Shared parsed struct or enum model.
///
/// # Returns
///
/// A `RedactSerialize` implementation when integration is enabled, or an
/// empty token stream otherwise.
///
/// # Errors
///
/// Returns a targeted error for a structurally invalid enum representation.
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
    serde: Option<&Path>,
    container_attributes: &SerdeContainerAttributes,
    model: &ContainerData<'_>,
) -> syn::Result<TokenStream> {
    let Some(serde) = serde else {
        return Ok(TokenStream::new());
    };

    let serialization_assertions = serialization_assertions(&input.ident, model, runtime);
    let body = match model {
        ContainerData::Struct(fields) => {
            struct_body(&input.ident, fields, runtime, serde, container_attributes)
        }
        ContainerData::Enum(variants) => {
            enum_body(&input.ident, variants, runtime, serde, container_attributes)?
        }
    };
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
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
                    __QubitRedactSerializer: #serde::Serializer,
                {
                    #(#serialization_assertions)*
                    #body
                }
            }
        }
    })
}

/// Generates serialization capability assertions for the shared model.
///
/// # Parameters
///
/// * `type_name` - Type receiving the hidden implementation.
/// * `model` - Parsed struct or enum model.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// Local helper functions for nested and map fields.
fn serialization_assertions(
    type_name: &syn::Ident,
    model: &ContainerData<'_>,
    runtime: &Path,
) -> Vec<TokenStream> {
    match model {
        ContainerData::Struct(fields) => {
            fields_serialization_assertions(type_name, fields, None, runtime)
        }
        ContainerData::Enum(variants) => variants
            .iter()
            .flat_map(|variant| {
                fields_serialization_assertions(
                    type_name,
                    variant.fields(),
                    Some(&variant.variant().ident),
                    runtime,
                )
            })
            .collect(),
    }
}

/// Generates serialization assertions for one field collection.
///
/// # Parameters
///
/// * `type_name` - Type receiving the hidden serialization implementation.
/// * `fields` - Parsed fields requiring capability assertions.
/// * `variant_name` - Owning variant for enum fields, or `None` for structs.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// Local helper functions asserting nested and map serialization capabilities.
fn fields_serialization_assertions(
    type_name: &syn::Ident,
    fields: &FieldsData<'_>,
    variant_name: Option<&syn::Ident>,
    runtime: &Path,
) -> Vec<TokenStream> {
    match fields {
        FieldsData::Named(fields) => fields
            .iter()
            .map(|parsed| {
                let field_name = parsed.identifier().to_string();
                let context = field_context(variant_name, &field_name);
                field_assertion::serialization(
                    type_name,
                    parsed.field(),
                    &context,
                    parsed.attributes().mode(),
                    runtime,
                )
            })
            .collect(),
        FieldsData::Unnamed(fields) => fields
            .iter()
            .map(|parsed| {
                let field_name = parsed.index().index.to_string();
                let context = field_context(variant_name, &field_name);
                field_assertion::serialization(
                    type_name,
                    parsed.field(),
                    &context,
                    parsed.attributes().mode(),
                    runtime,
                )
            })
            .collect(),
        FieldsData::Unit => Vec::new(),
    }
}
