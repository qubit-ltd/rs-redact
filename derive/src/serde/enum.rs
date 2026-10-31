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
use syn::Ident;
use syn::Path;
use syn::Result;

use super::internal::adjacent_variant_arm;
use super::internal::external_variant_arm;
use super::internal::internal_variant_arm;
use super::internal::untagged_variant_arm;
use super::source_function_path::SourceTypeContext;
use crate::attributes::SerdeContainerAttributes;
use crate::attributes::SerdeEnumRepresentation;
use crate::model::FieldsData;
use crate::model::VariantData;
/// Generates redacted serialization for an enum representation.
///
/// # Parameters
///
/// * `source_context` - Source type identity and generic context used to
///   resolve source paths and helpers.
/// * `recursive_target` - Source type name used to recognize self-recursive
///   field projections.
/// * `variants` - Parsed variants in declaration order.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved path to Serde.
/// * `container_attributes` - Validated naming and representation controls.
/// * `serializer` - Generated serializer type parameter used in error paths.
/// * `marker` - Fresh projection-only lifetime variant to reject.
/// * `legacy_nested` - Whether nested fields use the source serialization
///   bridge rather than borrowed view projections, affecting field access and
///   nested carrier selection.
///
/// # Returns
///
/// A match expression containing one serialization arm per variant.
///
/// # Errors
///
/// Returns an error when the selected representation is incompatible with a
/// variant shape or serialized field name.
#[allow(clippy::too_many_arguments)]
pub(super) fn enum_body(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    variants: &[VariantData<'_>],
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    serializer: &Ident,
    marker: &Ident,
    legacy_nested: bool,
) -> Result<TokenStream> {
    let arms = variants
        .iter()
        .map(|variant| {
            if variant.serde_attributes().skip() {
                return Ok(skipped_variant_arm(variant, serde, serializer));
            }
            match container_attributes.representation() {
                SerdeEnumRepresentation::ExternallyTagged => external_variant_arm(
                    source_context,
                    recursive_target,
                    variant,
                    runtime,
                    serde,
                    container_attributes,
                    legacy_nested,
                ),
                SerdeEnumRepresentation::InternallyTagged { tag } => internal_variant_arm(
                    source_context,
                    recursive_target,
                    variant,
                    runtime,
                    serde,
                    container_attributes,
                    tag,
                    legacy_nested,
                ),
                SerdeEnumRepresentation::AdjacentlyTagged { tag, content } => adjacent_variant_arm(
                    source_context,
                    recursive_target,
                    variant,
                    runtime,
                    serde,
                    container_attributes,
                    tag,
                    content,
                    legacy_nested,
                ),
                SerdeEnumRepresentation::Untagged => untagged_variant_arm(
                    source_context,
                    recursive_target,
                    variant,
                    runtime,
                    serde,
                    container_attributes,
                    legacy_nested,
                ),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let marker_arm = (!legacy_nested)
        .then(|| quote!(Self::#marker(_) => unreachable!("generated projection marker is never constructed"),));
    let source = if legacy_nested && !variants.is_empty() {
        quote!(self)
    } else {
        quote!(*self)
    };
    Ok(quote! {
        match #source {
            #(#arms,)*
            #marker_arm
        }
    })
}

/// Generates an erroring arm for a selected skipped variant.
///
/// # Parameters
///
/// * `variant` - Skipped variant being expanded.
/// * `serde` - Resolved path to Serde.
/// * `serializer` - Generated serializer type parameter used in the custom
///   error.
///
/// # Returns
///
/// A match arm returning Serde's custom skipped-variant error.
#[must_use]
#[inline]
fn skipped_variant_arm(variant: &VariantData<'_>, serde: &Path, serializer: &Ident) -> TokenStream {
    let variant_name = &variant.variant().ident;
    let pattern = wildcard_variant_pattern(variant);
    let message = format!("cannot serialize skipped redacted variant `{variant_name}`",);
    quote! {
        Self::#variant_name #pattern => ::core::result::Result::Err(
            <#serializer::Error as #serde::ser::Error>::custom(#message),
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
#[must_use]
#[inline]
fn wildcard_variant_pattern(variant: &VariantData<'_>) -> TokenStream {
    match variant.fields() {
        FieldsData::Named(_) => quote!({ .. }),
        FieldsData::Unnamed(_) => quote!((..)),
        FieldsData::Unit => TokenStream::new(),
    }
}
