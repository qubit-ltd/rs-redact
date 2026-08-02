// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tuple-field attribute parsing shared by structs and enum variants.

use syn::{
    FieldsUnnamed,
    Ident,
    Index,
};

use crate::{
    field_attributes::FieldAttributes,
    internal::UnnamedField,
    serde_attributes::SerdeAttributes,
};

/// Parses every unnamed field in source order.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed positional-field syntax retained by the
///   result.
///
/// # Parameters
///
/// * `fields` - Tuple fields to validate.
/// * `type_name` - Derived type used in targeted diagnostics.
/// * `serde_enabled` - Whether supported serde controls are validated.
///
/// # Returns
///
/// Parsed positional fields carrying stable zero-based indexes.
///
/// # Errors
///
/// Returns a targeted error when a field attribute is invalid.
pub(crate) fn parse<'a>(
    fields: &'a FieldsUnnamed,
    type_name: &Ident,
    serde_enabled: bool,
    require_explicit: bool,
) -> syn::Result<Vec<UnnamedField<'a>>> {
    fields
        .unnamed
        .iter()
        .enumerate()
        .map(|(position, field)| {
            let field_name = position.to_string();
            let attributes = FieldAttributes::parse(
                field,
                type_name,
                &field_name,
                require_explicit,
            )?;
            let serde_attributes = SerdeAttributes::parse(
                field,
                type_name,
                &field_name,
                serde_enabled,
            )?;
            Ok(UnnamedField::new(
                field,
                Index::from(position),
                attributes,
                serde_attributes,
            ))
        })
        .collect()
}
