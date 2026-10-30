// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Capability bounds for borrowed projections and source serialization.

use proc_macro2::TokenStream;
use quote::quote;
use syn::DeriveInput;
use syn::Field;
use syn::Ident;
use syn::Lifetime;
use syn::Path;
use syn::Type;

use super::super::recursive_projection;
use super::projection::projection_field_type;
use crate::attributes::SerdeAttributes;
use crate::model::ContainerData;
use crate::model::FieldMode;
use crate::model::FieldsData;
use crate::model::VariantData;

/// Collects capability predicates for the borrowed projection.
///
/// # Parameters
///
/// * `model` - Validated struct or enum fields.
/// * `parameters` - One generated type parameter per source field in traversal
///   order.
/// * `runtime` - Resolved runtime crate path.
/// * `serde` - Resolved Serde path.
/// * `lifetime` - Actual borrow lifetime of fields in this projection.
///
/// # Returns
///
/// Projection predicates matching each selected field mode.
///
/// # Panics
///
/// Panics if the generated parameter count does not match the model fields.
#[must_use]
pub(super) fn projection_bounds(
    input: &DeriveInput,
    model: &ContainerData<'_>,
    parameters: &[Ident],
    runtime: &Path,
    serde: &Path,
    lifetime: &Lifetime,
) -> Vec<TokenStream> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    match model {
        ContainerData::Struct(fields) => projection_group_bounds(
            input,
            fields,
            parameters,
            &mut offset,
            runtime,
            serde,
            lifetime,
            &mut result,
        ),
        ContainerData::Enum(variants) => {
            for variant in variants {
                if variant.serde_attributes().skip() {
                    offset += match variant.fields() {
                        FieldsData::Named(fields) => fields.len(),
                        FieldsData::Unnamed(fields) => fields.len(),
                        FieldsData::Unit => 0,
                    };
                    continue;
                }
                projection_group_bounds(
                    input,
                    variant.fields(),
                    parameters,
                    &mut offset,
                    runtime,
                    serde,
                    lifetime,
                    &mut result,
                );
            }
        }
    }
    result
}

/// Appends capability predicates for one field group.
///
/// # Parameters
///
/// * `fields` - Validated named, tuple, or unit fields.
/// * `parameters` - Generated parameters for every model field.
/// * `offset` - Index of this group, advanced past its fields.
/// * `runtime` - Resolved runtime crate path.
/// * `serde` - Resolved Serde path.
/// * `lifetime` - Borrow lifetime required of nested field projections.
/// * `result` - Destination for generated capability predicates.
///
/// # Panics
///
/// Panics if the parameter slice cannot cover the group at the supplied offset.
#[allow(clippy::too_many_arguments)]
fn projection_group_bounds(
    input: &DeriveInput,
    fields: &FieldsData<'_>,
    parameters: &[Ident],
    offset: &mut usize,
    runtime: &Path,
    serde: &Path,
    lifetime: &Lifetime,
    result: &mut Vec<TokenStream>,
) {
    match fields {
        FieldsData::Named(fields) => {
            for (index, field) in fields.iter().enumerate() {
                if field.serde_attributes().skip() {
                    continue;
                }
                if matches!(field.attributes().mode(), FieldMode::Nested)
                    && recursive_projection::shape(input, &field.field().ty).is_some()
                {
                    continue;
                }
                let parameter = projection_field_type(
                    input,
                    field.field(),
                    field.serde_attributes(),
                    &parameters[*offset + index],
                );
                match field.attributes().mode() {
                    FieldMode::Unmarked | FieldMode::Skip if field.serde_attributes().serialize_with().is_none() => {
                        result.push(quote!(#parameter: #serde::Serialize))
                    }
                    FieldMode::DisplayLevel(_) => result.push(quote!(#parameter: ::core::fmt::Display)),
                    FieldMode::Level(_) => {
                        result.push(quote!(#parameter: #runtime::domain::internal::RedactLevelSerialize))
                    }
                    FieldMode::KeyedBy(key) => {
                        result.push(
                            quote!(#parameter: #runtime::domain::internal::RedactLevelSerialize + #serde::Serialize),
                        );
                        if let Some(key_index) = fields.iter().position(|item| item.identifier() == key) {
                            let key_field = &fields[key_index];
                            let key_parameter = projection_field_type(
                                input,
                                key_field.field(),
                                key_field.serde_attributes(),
                                &parameters[*offset + key_index],
                            );
                            result.push(quote!(#key_parameter: ::core::convert::AsRef<str>));
                        }
                    }
                    FieldMode::Nested => {
                        let source = quote!(#runtime::domain::internal::RedactSerializeSource);
                        result.push(quote!(#parameter: #source));
                        result.push(quote!(<#parameter as #runtime::domain::internal::RedactSerializeSource>::RedactedFields<#lifetime>: #serde::Serialize));
                    }
                    FieldMode::Map => result.push(quote!(#parameter: #runtime::domain::internal::RedactMapSerialize)),
                    FieldMode::MapLevels { .. } => {
                        result.push(quote!(#parameter: #runtime::domain::internal::RedactMapKeySerialize))
                    }
                    FieldMode::Json => result.push(quote!(#parameter: #runtime::domain::internal::RedactJsonSerialize)),
                    _ => {}
                }
            }
            *offset += fields.len();
        }
        FieldsData::Unnamed(fields) => {
            for (index, field) in fields.iter().enumerate() {
                if field.serde_attributes().skip() {
                    continue;
                }
                if matches!(field.attributes().mode(), FieldMode::Nested)
                    && recursive_projection::shape(input, &field.field().ty).is_some()
                {
                    continue;
                }
                let parameter = projection_field_type(
                    input,
                    field.field(),
                    field.serde_attributes(),
                    &parameters[*offset + index],
                );
                match field.attributes().mode() {
                    FieldMode::Unmarked | FieldMode::Skip if field.serde_attributes().serialize_with().is_none() => {
                        result.push(quote!(#parameter: #serde::Serialize))
                    }
                    FieldMode::DisplayLevel(_) => result.push(quote!(#parameter: ::core::fmt::Display)),
                    FieldMode::Level(_) => {
                        result.push(quote!(#parameter: #runtime::domain::internal::RedactLevelSerialize))
                    }
                    FieldMode::Nested => {
                        let source = quote!(#runtime::domain::internal::RedactSerializeSource);
                        result.push(quote!(#parameter: #source));
                        result.push(quote!(<#parameter as #runtime::domain::internal::RedactSerializeSource>::RedactedFields<#lifetime>: #serde::Serialize));
                    }
                    FieldMode::Map => result.push(quote!(#parameter: #runtime::domain::internal::RedactMapSerialize)),
                    FieldMode::MapLevels { .. } => {
                        result.push(quote!(#parameter: #runtime::domain::internal::RedactMapKeySerialize))
                    }
                    FieldMode::Json => result.push(quote!(#parameter: #runtime::domain::internal::RedactJsonSerialize)),
                    _ => {}
                }
            }
            *offset += fields.len();
        }
        FieldsData::Unit => {}
    }
}

/// Collects the concrete source-field capabilities required by the generated
/// source implementation. Unlike the borrowed projection path, these bounds
/// do not quantify over an arbitrary source lifetime.
pub(super) fn source_bounds(model: &ContainerData<'_>, runtime: &Path, serde: &Path) -> Vec<TokenStream> {
    let mut result = Vec::new();
    let mut groups = Vec::new();
    match model {
        ContainerData::Struct(fields) => groups.push(fields),
        ContainerData::Enum(variants) => groups.extend(
            variants
                .iter()
                .filter(|variant| !variant.serde_attributes().skip())
                .map(VariantData::fields),
        ),
    }
    for fields in groups {
        source_group_bounds(fields, runtime, serde, &mut result);
    }
    result
}

/// Appends concrete capability bounds for one source field group.
fn source_group_bounds(fields: &FieldsData<'_>, runtime: &Path, serde: &Path, result: &mut Vec<TokenStream>) {
    match fields {
        FieldsData::Named(fields) => {
            for field in fields {
                let FieldMode::KeyedBy(key) = field.attributes().mode() else {
                    continue;
                };
                if let Some(key_field) = fields.iter().find(|candidate| candidate.identifier() == key) {
                    let key_type = &key_field.field().ty;
                    result.push(quote!(#key_type: ::core::convert::AsRef<str>));
                }
            }
            for field in fields {
                source_field_bound(
                    field.field(),
                    field.attributes().mode(),
                    field.serde_attributes(),
                    runtime,
                    serde,
                    result,
                );
            }
        }
        FieldsData::Unnamed(fields) => {
            for field in fields {
                source_field_bound(
                    field.field(),
                    field.attributes().mode(),
                    field.serde_attributes(),
                    runtime,
                    serde,
                    result,
                );
            }
        }
        FieldsData::Unit => {}
    }
}

/// Appends capability bounds for one concrete field.
fn source_field_bound(
    field: &Field,
    mode: &FieldMode,
    serde_attributes: &SerdeAttributes,
    runtime: &Path,
    serde: &Path,
    result: &mut Vec<TokenStream>,
) {
    let ty = &field.ty;
    if serde_attributes.skip() {
        return;
    }
    match mode {
        FieldMode::Unmarked | FieldMode::Skip if serde_attributes.serialize_with().is_none() => {
            let serialize_type = match ty {
                Type::Reference(reference) => {
                    let mut target = reference.elem.as_ref();
                    while let Type::Reference(reference) = target {
                        target = reference.elem.as_ref();
                    }
                    target
                }
                _ => ty,
            };
            result.push(quote!(#serialize_type: #serde::Serialize));
        }
        FieldMode::DisplayLevel(_) => result.push(quote!(#ty: ::core::fmt::Display)),
        FieldMode::Level(_) => result.push(quote!(#ty: #runtime::domain::internal::RedactLevelSerialize)),
        FieldMode::Nested => result.push(quote!(#ty: #runtime::domain::internal::RedactSerialize)),
        FieldMode::Map => result.push(quote!(#ty: #runtime::domain::internal::RedactMapSerialize)),
        FieldMode::MapLevels { .. } => {
            result.push(quote!(#ty: #runtime::domain::internal::RedactMapKeySerialize));
        }
        FieldMode::KeyedBy(_) => {
            result.push(quote!(#ty: #runtime::domain::internal::RedactLevelSerialize + #serde::Serialize));
        }
        FieldMode::Json => result.push(quote!(#ty: #runtime::domain::internal::RedactJsonSerialize)),
        FieldMode::Unmarked | FieldMode::Skip => {}
    }
}
