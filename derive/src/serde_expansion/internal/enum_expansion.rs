// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Enum representation dispatch and skipped-variant expansion.

use proc_macro2::TokenStream;
use quote::quote;
use syn::Path;

use crate::{
    internal::{FieldsData, VariantData},
    serde_container_attributes::SerdeContainerAttributes,
    serde_enum_representation::SerdeEnumRepresentation,
};

use super::{
    adjacently_tagged::adjacent_variant_arm, externally_tagged::external_variant_arm,
    internally_tagged::internal_variant_arm, untagged::untagged_variant_arm,
};

/// Generates redacted serialization for an enum representation.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated serialization implementation.
/// * `variants` - Parsed variants in declaration order.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved path to Serde.
/// * `container_attributes` - Validated naming and representation controls.
///
/// # Returns
///
/// A match expression containing one serialization arm per variant.
///
/// # Errors
///
/// Returns an error when the selected representation is incompatible with a
/// variant shape or serialized field name.
pub(super) fn enum_body(
    type_name: &syn::Ident,
    variants: &[VariantData<'_>],
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> syn::Result<TokenStream> {
    let arms = variants
        .iter()
        .map(|variant| {
            if variant.serde_attributes().skip() {
                return Ok(skipped_variant_arm(variant, serde));
            }
            match container_attributes.representation() {
                SerdeEnumRepresentation::ExternallyTagged => {
                    external_variant_arm(type_name, variant, runtime, serde, container_attributes)
                }
                SerdeEnumRepresentation::InternallyTagged { tag } => internal_variant_arm(
                    type_name,
                    variant,
                    runtime,
                    serde,
                    container_attributes,
                    tag,
                ),
                SerdeEnumRepresentation::AdjacentlyTagged { tag, content } => adjacent_variant_arm(
                    type_name,
                    variant,
                    runtime,
                    serde,
                    container_attributes,
                    tag,
                    content,
                ),
                SerdeEnumRepresentation::Untagged => {
                    untagged_variant_arm(type_name, variant, runtime, serde, container_attributes)
                }
            }
        })
        .collect::<syn::Result<Vec<_>>>()?;
    Ok(quote! {
        match self {
            #(#arms),*
        }
    })
}

/// Generates an erroring arm for a selected skipped variant.
///
/// # Parameters
///
/// * `variant` - Skipped variant being expanded.
/// * `serde` - Resolved path to Serde.
///
/// # Returns
///
/// A match arm returning Serde's custom skipped-variant error.
#[inline]
fn skipped_variant_arm(variant: &VariantData<'_>, serde: &Path) -> TokenStream {
    let variant_name = &variant.variant().ident;
    let pattern = wildcard_variant_pattern(variant);
    let message = format!("cannot serialize skipped redacted variant `{variant_name}`",);
    quote! {
        Self::#variant_name #pattern => ::core::result::Result::Err(
            <__QubitRedactSerializer::Error as #serde::ser::Error>::custom(#message),
        )
    }
}

/// Generates a wildcard suffix for one variant pattern.
///
/// # Parameters
///
/// * `variant` - Variant whose field shape determines the pattern.
///
/// # Returns
///
/// A named, unnamed, or empty wildcard suffix.
#[inline]
fn wildcard_variant_pattern(variant: &VariantData<'_>) -> TokenStream {
    match variant.fields() {
        FieldsData::Named(_) => quote!({ .. }),
        FieldsData::Unnamed(_) => quote!((..)),
        FieldsData::Unit => TokenStream::new(),
    }
}
