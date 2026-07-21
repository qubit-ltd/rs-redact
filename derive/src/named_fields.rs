// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Named-struct validation and field-attribute parsing.

use syn::{
    Data,
    DeriveInput,
    Fields,
};

use crate::{
    field_attributes::FieldAttributes,
    internal::NamedField,
    serde_attributes::SerdeAttributes,
};

/// Validates and parses every named field on a derive input.
///
/// # Parameters
///
/// * `input` - Complete derive input to validate.
/// * `derive_name` - Derive name used in targeted shape diagnostics.
/// * `serde_enabled` - Whether supported serde field controls are validated.
///
/// # Returns
///
/// Parsed fields in source order.
///
/// # Errors
///
/// Returns a targeted error when the input is not a named-field struct, a
/// field lacks an identifier, or a field attribute is invalid.
pub(crate) fn parse<'a>(
    input: &'a DeriveInput,
    derive_name: &str,
    serde_enabled: bool,
) -> syn::Result<Vec<NamedField<'a>>> {
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => fields,
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    format!(
                        "{derive_name} can only be derived for structs with named fields",
                    ),
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                format!(
                    "{derive_name} can only be derived for structs with named fields",
                ),
            ));
        }
    };

    fields
        .named
        .iter()
        .map(|field| {
            let identifier = field.ident.as_ref().ok_or_else(|| {
                syn::Error::new_spanned(
                    field,
                    format!(
                        "{derive_name} requires every field to have a name",
                    ),
                )
            })?;
            let attributes =
                FieldAttributes::parse(field, &input.ident, identifier)?;
            let serde_attributes = SerdeAttributes::parse(
                field,
                &input.ident,
                identifier,
                serde_enabled,
            )?;
            Ok(NamedField::new(
                field,
                identifier,
                attributes,
                serde_attributes,
            ))
        })
        .collect()
}
