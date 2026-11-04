// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redacted serialization expansion for struct shapes.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::quote_spanned;
use syn::Path;
use syn::spanned::Spanned;

use super::field::field_context;
use super::field::field_is_skipped;
use super::field::projected_raw;
use super::field::raw_identifier;
use super::field::serialized_carrier;
use super::field_access::FieldAccess;
use super::internal::field_events::field_count;
use super::internal::field_events::named_field_event;
use super::internal::field_events::positional_field_event;
use super::internal::field_plan::prepare_field_plan;
use super::internal::serialized_field_plan::SerializedFieldPlan;
use super::source_function_path::SourceTypeContext;
use crate::attributes::SerdeContainerAttributes;
use crate::model::FieldMode;
use crate::model::FieldsData;
use crate::model::NamedField;
use crate::model::UnnamedField;
/// Generates redacted serialization for one struct shape.
///
/// # Parameters
///
/// * `source_context` - Source type and generic context used to resolve source
///   paths and helpers.
/// * `recursive_target` - Source type name used to recognize self-recursive
///   field projections.
/// * `fields` - Parsed named, unnamed, or unit fields.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved path to Serde.
/// * `container_attributes` - Validated container naming controls.
/// * `legacy_nested` - Whether nested fields use the source serialization
///   bridge rather than borrowed view projections, affecting field access and
///   nested carrier selection.
///
/// # Returns
///
/// A serializer expression preserving the source struct shape.
///
/// # Panics
///
/// Panics if transparent mode is requested for a named shape with no field.
#[must_use]
pub(super) fn struct_body(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    fields: &FieldsData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    legacy_nested: bool,
) -> TokenStream {
    match fields {
        FieldsData::Named(fields) if container_attributes.transparent() => transparent_named_struct_body(
            source_context,
            recursive_target,
            &fields[0],
            runtime,
            serde,
            container_attributes,
            legacy_nested,
        ),
        FieldsData::Named(fields) => named_struct_body(
            source_context,
            recursive_target,
            fields,
            runtime,
            serde,
            container_attributes,
            legacy_nested,
        ),
        FieldsData::Unnamed(fields) if fields.len() == 1 && container_attributes.transparent() => newtype_struct_body(
            source_context,
            recursive_target,
            &fields[0],
            runtime,
            serde,
            container_attributes,
            legacy_nested,
            true,
        ),
        FieldsData::Unnamed(fields) if fields.len() == 1 => newtype_struct_body(
            source_context,
            recursive_target,
            &fields[0],
            runtime,
            serde,
            container_attributes,
            legacy_nested,
            false,
        ),
        FieldsData::Unnamed(fields) => tuple_struct_body(
            source_context,
            recursive_target,
            fields,
            runtime,
            serde,
            container_attributes,
            legacy_nested,
        ),
        FieldsData::Unit => {
            let serialized_name = container_attributes.name();
            quote! {
                #serde::Serializer::serialize_unit_struct(
                    serializer,
                    #serialized_name,
                )
            }
        }
    }
}

/// Generates transparent serialization for a single named field.
///
/// The field is forwarded directly unless Serde unconditionally skips it, in
/// which case a unit struct is emitted. `skip_serializing_if` is not evaluated
/// for transparent forwarding. Redaction `skip` remains policy-dependent: it
/// emits a unit struct while redaction is enabled and forwards the field when
/// the policy is disabled.
///
/// # Parameters
///
/// * `source_context` - Source type and generic context used to resolve source
///   paths and helpers.
/// * `recursive_target` - Source type name used to recognize self-recursive
///   field projections.
/// * `parsed` - Validated single named field and its controls.
/// * `runtime` - Resolved runtime crate path.
/// * `serde` - Resolved Serde path.
/// * `container_attributes` - Validated container naming controls.
/// * `legacy_nested` - Whether nested fields use the source serialization
///   bridge rather than borrowed view projections, affecting field access and
///   nested carrier selection.
///
/// # Returns
///
/// A direct serializer expression, or a unit-struct expression for an
/// unconditionally skipped field or an enabled redaction `skip`.
#[must_use]
fn transparent_named_struct_body(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    parsed: &NamedField<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    legacy_nested: bool,
) -> TokenStream {
    let type_name = source_context.ident;
    let serialized_name = container_attributes.name();
    if field_is_skipped(parsed.serde_attributes()) {
        return quote! {
            #serde::Serializer::serialize_unit_struct(serializer, #serialized_name)
        };
    }
    let field = parsed.field();
    let identifier = parsed.identifier();
    let raw_name = raw_identifier(identifier);
    let raw_member = if legacy_nested {
        quote_spanned!(field.span()=> &self.#identifier)
    } else {
        quote_spanned!(field.span()=> self.#identifier)
    };
    let raw = projected_raw(raw_member, parsed.serde_attributes(), legacy_nested);
    let key_raw = match parsed.attributes().mode() {
        FieldMode::KeyedBy(key) if legacy_nested => Some(quote_spanned!(field.span()=> &self.#key)),
        FieldMode::KeyedBy(key) => Some(quote_spanned!(field.span()=> self.#key)),
        _ => None,
    };
    let context = field_context(None, None, &raw_name);
    let value = serialized_carrier(
        type_name,
        recursive_target,
        field,
        &context,
        parsed.attributes().mode(),
        runtime,
        parsed.serde_attributes().serialize_with(),
        FieldAccess {
            raw: raw.clone(),
            key_raw,
        },
        legacy_nested,
    );
    let condition = if matches!(parsed.attributes().mode(), FieldMode::Skip) {
        quote!(policy.is_disabled())
    } else {
        quote!(true)
    };
    quote! {
        if #condition {
            let __qubit_redact_serialized_0 = #value;
            #serde::Serialize::serialize(&__qubit_redact_serialized_0, serializer)
        } else {
            #serde::Serializer::serialize_unit_struct(serializer, #serialized_name)
        }
    }
}

/// Generates named-struct serialization.
///
/// # Parameters
///
/// * `source_context` - Source type and generic context used to resolve source
///   paths and helpers.
/// * `recursive_target` - Source type name used to recognize self-recursive
///   field projections.
/// * `fields` - Parsed named fields in declaration order.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved path to Serde.
/// * `container_attributes` - Validated container naming controls.
/// * `legacy_nested` - Whether nested fields use the source serialization
///   bridge rather than borrowed view projections, affecting field access and
///   nested carrier selection.
///
/// # Returns
///
/// A `SerializeStruct` expression containing each selected field.
///
/// # Panics
///
/// Panics if a keyed field refers to a sibling that was not validated.
#[must_use]
fn named_struct_body(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    fields: &[NamedField<'_>],
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    legacy_nested: bool,
) -> TokenStream {
    let mut plans = Vec::<SerializedFieldPlan>::new();

    for (position, parsed) in fields.iter().enumerate() {
        if field_is_skipped(parsed.serde_attributes()) {
            continue;
        }
        let field = parsed.field();
        let identifier = parsed.identifier();
        let raw_name = raw_identifier(identifier);
        let serialized_name = parsed
            .serde_attributes()
            .rename()
            .map_or_else(|| container_attributes.rename_struct_field(&raw_name), str::to_owned);
        let raw_member = if legacy_nested {
            quote_spanned!(field.span()=> &self.#identifier)
        } else {
            quote_spanned!(field.span()=> self.#identifier)
        };
        let key_raw = match parsed.attributes().mode() {
            FieldMode::KeyedBy(key) if legacy_nested => Some(quote_spanned!(field.span()=> &self.#key)),
            FieldMode::KeyedBy(key) => Some(quote_spanned!(field.span()=> self.#key)),
            _ => None,
        };
        let key_raw = key_raw.map(|raw| {
            let FieldMode::KeyedBy(key) = parsed.attributes().mode() else {
                unreachable!()
            };
            let key_field = fields
                .iter()
                .find(|candidate| candidate.identifier() == key)
                .expect("keyed_by sibling was validated");
            projected_raw(raw, key_field.serde_attributes(), legacy_nested)
        });
        let context = field_context(None, None, &raw_name);
        if let Some(plan) = prepare_field_plan(
            source_context,
            recursive_target,
            field,
            &context,
            parsed.attributes().mode(),
            parsed.serde_attributes(),
            runtime,
            FieldAccess {
                raw: raw_member,
                key_raw,
            },
            legacy_nested,
            position,
            Some(serialized_name),
            None,
        ) {
            plans.push(plan);
        }
    }

    let setups = plans.iter().map(|plan| &plan.setup);
    let conditions = plans.iter().map(|plan| plan.included.clone()).collect::<Vec<_>>();
    let count_setup = field_count(&conditions, 0);
    let trait_path: syn::Path = syn::parse_quote!(#serde::ser::SerializeStruct);
    let state = quote!(&mut state);
    let serialized_name = container_attributes.name();
    let calls = plans.iter().map(|plan| {
        let carrier = {
            let carrier = &plan.carrier;
            quote!(#carrier)
        };
        named_field_event(
            &trait_path,
            &state,
            &carrier,
            plan.serialized_name.as_deref().expect("named field has a name"),
            plan.skip_event.as_ref(),
        )
    });
    quote! {
        #(#setups)*
        #count_setup
        #runtime::domain::internal::admit_serializer_items(&serializer, field_count)?;
        let mut state = #serde::Serializer::serialize_struct(
            serializer,
            #serialized_name,
            field_count,
        )?;
        #(#calls)*
        #serde::ser::SerializeStruct::end(state)
    }
}

/// Generates newtype-struct serialization.
///
/// # Parameters
///
/// * `source_context` - Source type and generic context used to resolve source
///   paths and helpers.
/// * `recursive_target` - Source type name used to recognize self-recursive
///   field projections.
/// * `parsed` - Parsed newtype field.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved path to Serde.
/// * `container_attributes` - Validated container naming controls.
/// * `legacy_nested` - Whether nested fields use the source serialization
///   bridge rather than borrowed view projections, affecting field access and
///   nested carrier selection.
/// * `transparent` - Whether to forward the field's serialized value directly
///   or preserve the newtype-struct serializer event.
///
/// # Returns
///
/// A direct transparent value or a newtype serializer expression. A
/// unit-struct expression is used for an unconditionally skipped field or, in
/// transparent mode, an enabled redaction `skip`.
#[must_use]
#[allow(clippy::too_many_arguments)]
fn newtype_struct_body(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    parsed: &UnnamedField<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    legacy_nested: bool,
    transparent: bool,
) -> TokenStream {
    let type_name = source_context.ident;
    let serialized_name = container_attributes.name();
    if field_is_skipped(parsed.serde_attributes()) {
        return quote! {
            #serde::Serializer::serialize_unit_struct(serializer, #serialized_name)
        };
    }
    let field = parsed.field();
    let index = parsed.index();
    let projection_field = format_ident!("__qubit_redact_field_{}", index.index, span = field.span());
    let raw_member = if legacy_nested {
        quote_spanned!(field.span()=> &self.#index)
    } else {
        quote_spanned!(field.span()=> self.#projection_field)
    };
    let raw = projected_raw(raw_member, parsed.serde_attributes(), legacy_nested);
    let context = field_context(None, None, &index.index.to_string());
    let value = serialized_carrier(
        type_name,
        recursive_target,
        field,
        &context,
        parsed.attributes().mode(),
        runtime,
        parsed.serde_attributes().serialize_with(),
        FieldAccess {
            raw: raw.clone(),
            key_raw: None,
        },
        legacy_nested,
    );
    let condition = if matches!(parsed.attributes().mode(), FieldMode::Skip) {
        quote!(policy.is_disabled())
    } else {
        quote!(true)
    };
    if transparent {
        quote! {
            if #condition {
                let __qubit_redact_serialized_0 = #value;
                #serde::Serialize::serialize(&__qubit_redact_serialized_0, serializer)
            } else {
                #serde::Serializer::serialize_unit_struct(serializer, #serialized_name)
            }
        }
    } else {
        quote! {
            if #condition {
                let __qubit_redact_serialized_0 = #value;
                #serde::Serializer::serialize_newtype_struct(
                    serializer,
                    #serialized_name,
                    &__qubit_redact_serialized_0,
                )
            } else {
                #serde::Serializer::serialize_unit_struct(serializer, #serialized_name)
            }
        }
    }
}

/// Generates tuple-struct serialization.
///
/// # Parameters
///
/// * `source_context` - Source type and generic context used to resolve source
///   paths and helpers.
/// * `recursive_target` - Source type name used to recognize self-recursive
///   field projections.
/// * `fields` - Parsed positional fields in declaration order.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved path to Serde.
/// * `container_attributes` - Validated container naming controls.
/// * `legacy_nested` - Whether nested fields use the source serialization
///   bridge rather than borrowed view projections, affecting field access and
///   nested carrier selection.
///
/// # Returns
///
/// A `SerializeTupleStruct` expression containing each selected field.
#[must_use]
fn tuple_struct_body(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    fields: &[UnnamedField<'_>],
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    legacy_nested: bool,
) -> TokenStream {
    let mut plans = Vec::<SerializedFieldPlan>::new();
    for (position, parsed) in fields.iter().enumerate() {
        if field_is_skipped(parsed.serde_attributes()) {
            continue;
        }
        let field = parsed.field();
        let index = parsed.index();
        let projection_field = format_ident!("__qubit_redact_field_{}", index.index, span = field.span());
        let raw_member = if legacy_nested {
            quote_spanned!(field.span()=> &self.#index)
        } else {
            quote_spanned!(field.span()=> self.#projection_field)
        };
        let context = field_context(None, None, &index.index.to_string());
        if let Some(plan) = prepare_field_plan(
            source_context,
            recursive_target,
            field,
            &context,
            parsed.attributes().mode(),
            parsed.serde_attributes(),
            runtime,
            FieldAccess {
                raw: raw_member,
                key_raw: None,
            },
            legacy_nested,
            position,
            None,
            None,
        ) {
            plans.push(plan);
        }
    }
    let setups = plans.iter().map(|plan| &plan.setup);
    let conditions = plans.iter().map(|plan| plan.included.clone()).collect::<Vec<_>>();
    let count_setup = field_count(&conditions, 0);
    let trait_path: syn::Path = syn::parse_quote!(#serde::ser::SerializeTupleStruct);
    let method: syn::Ident = syn::parse_quote!(serialize_field);
    let state = quote!(&mut state);
    let serialized_name = container_attributes.name();
    let calls = plans.iter().map(|plan| {
        let carrier = {
            let carrier = &plan.carrier;
            quote!(#carrier)
        };
        positional_field_event(&trait_path, &method, &state, &carrier)
    });
    quote! {
        #(#setups)*
        #count_setup
        #runtime::domain::internal::admit_serializer_items(&serializer, field_count)?;
        let mut state = #serde::Serializer::serialize_tuple_struct(
            serializer,
            #serialized_name,
            field_count,
        )?;
        #(#calls)*
        #serde::ser::SerializeTupleStruct::end(state)
    }
}
