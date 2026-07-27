// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Single parsing boundary for all supported derive input shapes.

use syn::{Data, DeriveInput, Fields};

use crate::{
    internal::{ContainerData, FieldsData, VariantData},
    named_fields,
    serde_variant_attributes::SerdeVariantAttributes,
    unnamed_fields,
};

/// Parses one derive input into the shared semantic model.
///
/// # Parameters
///
/// * `input` - Complete derive input to validate.
/// * `derive_name` - Derive name used in targeted shape diagnostics.
/// * `serde_enabled` - Whether supported serde controls are validated.
///
/// # Returns
///
/// A validated struct or enum model retaining source order and spans.
///
/// # Errors
///
/// Returns a targeted error for unions or invalid field attributes.
pub(crate) fn parse<'a>(
    input: &'a DeriveInput,
    derive_name: &str,
    serde_enabled: bool,
) -> syn::Result<ContainerData<'a>> {
    match &input.data {
        Data::Struct(data) => Ok(ContainerData::Struct(parse_fields(
            &data.fields,
            &input.ident,
            serde_enabled,
        )?)),
        Data::Enum(data) => {
            let variants = data
                .variants
                .iter()
                .enumerate()
                .map(|(index, variant)| {
                    let serde_attributes =
                        SerdeVariantAttributes::parse(variant, &input.ident, serde_enabled)?;
                    let fields = parse_fields(&variant.fields, &input.ident, serde_enabled)?;
                    Ok(VariantData::new(
                        variant,
                        index as u32,
                        fields,
                        serde_attributes,
                    ))
                })
                .collect::<syn::Result<Vec<_>>>()?;
            Ok(ContainerData::Enum(variants))
        }
        Data::Union(_) => Err(syn::Error::new_spanned(
            input,
            format!("{derive_name} cannot be derived for unions"),
        )),
    }
}

/// Parses one named, unnamed, or unit field collection.
///
/// # Parameters
///
/// * `fields` - Struct or variant fields to validate.
/// * `type_name` - Derived type used in targeted diagnostics.
/// * `serde_enabled` - Whether supported serde controls are validated.
///
/// # Returns
///
/// Parsed fields preserving their declared shape.
///
/// # Errors
///
/// Returns a targeted error when a field attribute is invalid.
fn parse_fields<'a>(
    fields: &'a Fields,
    type_name: &syn::Ident,
    serde_enabled: bool,
) -> syn::Result<FieldsData<'a>> {
    match fields {
        Fields::Named(fields) => Ok(FieldsData::Named(named_fields::parse(
            fields,
            type_name,
            serde_enabled,
        )?)),
        Fields::Unnamed(fields) => Ok(FieldsData::Unnamed(unnamed_fields::parse(
            fields,
            type_name,
            serde_enabled,
        )?)),
        Fields::Unit => Ok(FieldsData::Unit),
    }
}
