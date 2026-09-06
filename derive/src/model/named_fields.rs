// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Named-field attribute parsing shared by structs and enum variants.

use syn::Error;
use syn::FieldsNamed;
use syn::Ident;
use syn::Result;

use super::FieldMode;
use super::NamedField;
use crate::attributes::FieldAttributes;
use crate::attributes::SerdeAttributes;
/// Validates and parses every named field in source order.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed named-field syntax retained by the result.
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
///
/// # Panics
///
/// Panics only if a `syn::FieldsNamed` entry has no identifier, which violates
/// the invariant guaranteed by `syn` for named fields.
pub(crate) fn parse<'a>(
    fields: &'a FieldsNamed,
    type_name: &Ident,
    serde_enabled: bool,
) -> Result<Vec<NamedField<'a>>> {
    let parsed = fields
        .named
        .iter()
        .map(|field| {
            let identifier = field.ident.as_ref().expect("syn named fields always have identifiers");
            let field_name = identifier.to_string();
            let attributes = FieldAttributes::parse(field, type_name, &field_name)?;
            let serde_attributes = SerdeAttributes::parse(field, type_name, &field_name, serde_enabled)?;
            serde_attributes.validate_redaction_mode(field, type_name, &field_name, attributes.mode())?;
            Ok(NamedField::new(field, identifier, attributes, serde_attributes))
        })
        .collect::<Result<Vec<_>>>()?;
    validate_keyed_by_fields(&parsed, type_name)?;
    Ok(parsed)
}

/// Validates sibling-key references after all named fields are parsed.
fn validate_keyed_by_fields(fields: &[NamedField<'_>], type_name: &Ident) -> Result<()> {
    for field in fields {
        let FieldMode::KeyedBy(key) = field.attributes().mode() else {
            continue;
        };
        let field_name = field.identifier().to_string();
        if key == field.identifier() {
            return Err(Error::new_spanned(
                key,
                format!(
                    "Redact derive for `{type_name}` field `{field_name}` cannot use \
                     `keyed_by` to reference itself",
                ),
            ));
        }
        if !fields.iter().any(|candidate| candidate.identifier() == key) {
            return Err(Error::new_spanned(
                key,
                format!(
                    "Redact derive for `{type_name}` field `{field_name}` references \
                     missing sibling field `{key}` in `keyed_by`",
                ),
            ));
        }
    }
    Ok(())
}
