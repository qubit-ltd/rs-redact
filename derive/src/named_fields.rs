// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Named-field attribute parsing shared by structs and enum variants.

use syn::{FieldsNamed, Ident};

use crate::{
    field_attributes::FieldAttributes, internal::NamedField, serde_attributes::SerdeAttributes,
};

/// Validates and parses every named field in source order.
///
/// # Parameters
///
/// * `fields` - Named fields to validate.
/// * `type_name` - Derived type used in targeted diagnostics.
/// * `serde_enabled` - Whether supported serde field controls are validated.
///
/// # Returns
///
/// Parsed fields in source order.
///
/// # Errors
///
/// Returns a targeted error when a field attribute is invalid.
pub(crate) fn parse<'a>(
    fields: &'a FieldsNamed,
    type_name: &Ident,
    serde_enabled: bool,
) -> syn::Result<Vec<NamedField<'a>>> {
    fields
        .named
        .iter()
        .map(|field| {
            let identifier = field
                .ident
                .as_ref()
                .expect("syn named fields always have identifiers");
            let field_name = identifier.to_string();
            let attributes = FieldAttributes::parse(field, type_name, &field_name)?;
            let serde_attributes =
                SerdeAttributes::parse(field, type_name, &field_name, serde_enabled)?;
            Ok(NamedField::new(
                field,
                identifier,
                attributes,
                serde_attributes,
            ))
        })
        .collect()
}
