// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowing `Redact` implementation generation.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::quote_spanned;
use syn::DeriveInput;
use syn::Field;
use syn::Ident;
use syn::Path;
use syn::Result;
use syn::spanned::Spanned;

use super::assertions;
use super::format;
use crate::attributes::ContainerAttributes;
use crate::attributes::SerdeContainerAttributes;
use crate::attributes::resolve_serde_path;
use crate::model;
use crate::model::ContainerData;
use crate::model::FieldMode;
use crate::model::FieldsData;
use crate::model::VariantData;
use crate::serde;
/// Expands a struct into its runtime `Redact` implementation.
///
/// # Parameters
///
/// * `input` - Parsed derive input whose generics and fields are preserved.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
///
/// # Returns
///
/// Generated borrowing redaction plus optional formatting and Serde tokens.
///
/// # Errors
///
/// Returns a targeted syntax error when container or field controls are
/// invalid or when Serde controls conflict with the input shape.
pub(crate) fn expand(input: &DeriveInput, runtime: &Path) -> Result<TokenStream> {
    let container_attributes = ContainerAttributes::parse(input)?;
    expand_with_container_attributes(input, runtime, container_attributes)
}

/// Generates the implementation from already-validated container controls.
///
/// # Parameters
///
/// * `input` - Complete derive input to expand.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
/// * `container_attributes` - Validated controls selected for the expansion.
///
/// # Returns
///
/// Generated implementations for the validated input.
///
/// # Errors
///
/// Returns a targeted syntax error when field, Serde, or capability controls
/// are incompatible with the input.
fn expand_with_container_attributes(
    input: &DeriveInput,
    runtime: &Path,
    container_attributes: ContainerAttributes,
) -> Result<TokenStream> {
    let model = model::parse(input, "Redact", container_attributes.serde_enabled())?;
    let serde = container_attributes
        .serde_enabled()
        .then(|| resolve_serde_path(input))
        .transpose()?;
    let serde_container_attributes = SerdeContainerAttributes::parse(input, container_attributes.serde_enabled())?;
    let serde_impl = serde::expand(input, runtime, serde.as_ref(), &serde_container_attributes, &model)?;
    let mut redaction_generics = input.generics.clone();
    assertions::add_redact_bounds(&mut redaction_generics, &model, runtime);
    let write_body = match &model {
        ContainerData::Struct(fields) if container_attributes.transparent() => {
            writer_transparent_struct_body(fields, runtime)
        }
        ContainerData::Struct(fields) => writer_struct_body(&input.ident, fields, runtime),
        ContainerData::Enum(variants) => writer_enum_body(variants, runtime),
    };
    let format_impl = format::expand(input, runtime, &container_attributes, &redaction_generics);
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = redaction_generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #runtime::Redact for #name #type_generics #where_clause {
            fn write_redacted(
                &self,
                writer: &mut #runtime::RedactionWriter<'_>,
            ) {
                #write_body
            }
        }
        #format_impl
        #serde_impl
    })
}

/// Generates one classified field without a nominal struct wrapper.
fn writer_transparent_struct_body(fields: &FieldsData<'_>, runtime: &Path) -> TokenStream {
    let call = match fields {
        FieldsData::Named(fields) => {
            let field = fields.first().expect("transparent shape was validated");
            let identifier = field.identifier();
            let key_access = match field.attributes().mode() {
                FieldMode::KeyedBy(key) => Some(quote!(&self.#key)),
                _ => None,
            };
            let name = identifier.to_string();
            writer_field_call(
                field.field(),
                &name,
                &name,
                field.attributes().mode(),
                quote!(&self.#identifier),
                key_access,
                runtime,
            )
        }
        FieldsData::Unnamed(fields) => {
            let field = fields.first().expect("transparent shape was validated");
            let index = field.index();
            let name = index.index.to_string();
            writer_field_call(
                field.field(),
                &name,
                &name,
                field.attributes().mode(),
                quote!(&self.#index),
                None,
                runtime,
            )
        }
        FieldsData::Unit => {
            unreachable!("transparent unit structs are rejected")
        }
    };
    quote! {
        writer.transparent(|__fields| {
            #call
        });
    }
}

/// Generates a structured writer body for one struct.
fn writer_struct_body(type_name: &Ident, fields: &FieldsData<'_>, runtime: &Path) -> TokenStream {
    match fields {
        FieldsData::Named(fields) => {
            let calls = fields.iter().filter_map(|field| {
                let identifier = field.identifier();
                let key_access = match field.attributes().mode() {
                    FieldMode::KeyedBy(key) => Some(quote!(&self.#key)),
                    _ => None,
                };
                writer_field_call(
                    field.field(),
                    &field.identifier().to_string(),
                    &field.identifier().to_string(),
                    field.attributes().mode(),
                    quote!(&self.#identifier),
                    key_access,
                    runtime,
                )
            });
            quote! {
                writer.record(stringify!(#type_name), |__fields| {
                    #(#calls)*
                });
            }
        }
        FieldsData::Unnamed(fields) => {
            let calls = fields.iter().filter_map(|field| {
                let index = field.index();
                writer_field_call(
                    field.field(),
                    &index.index.to_string(),
                    &index.index.to_string(),
                    field.attributes().mode(),
                    quote!(&self.#index),
                    None,
                    runtime,
                )
            });
            quote! {
                writer.tuple(stringify!(#type_name), |__fields| {
                    #(#calls)*
                });
            }
        }
        FieldsData::Unit => {
            quote! { writer.record(stringify!(#type_name), |_| {}); }
        }
    }
}

/// Generates a structured writer match for one enum.
fn writer_enum_body(variants: &[VariantData<'_>], runtime: &Path) -> TokenStream {
    let arms = variants.iter().map(|variant| {
        let variant_name = &variant.variant().ident;
        match variant.fields() {
            FieldsData::Named(fields) => {
                let bindings = fields
                    .iter()
                    .enumerate()
                    .map(|(position, field)| {
                        format_ident!("__qubit_redact_field_{position}", span = field.field().span())
                    })
                    .collect::<Vec<_>>();
                let patterns = fields.iter().zip(&bindings).map(|(field, binding)| {
                    let identifier = field.identifier();
                    quote!(#identifier: #binding)
                });
                let calls = fields.iter().zip(&bindings).filter_map(|(field, binding)| {
                    let identifier = field.identifier();
                    let field_name = identifier.to_string();
                    let context = variant_field_context(variant.index(), variant_name, &field_name);
                    let key_access = match field.attributes().mode() {
                        FieldMode::KeyedBy(key) => {
                            let position = fields
                                .iter()
                                .position(|candidate| candidate.identifier() == key)
                                .expect("keyed_by sibling was validated");
                            let key_binding = &bindings[position];
                            Some(quote!(#key_binding))
                        }
                        _ => None,
                    };
                    writer_field_call(
                        field.field(),
                        &field_name,
                        &context,
                        field.attributes().mode(),
                        quote!(#binding),
                        key_access,
                        runtime,
                    )
                });
                quote! {
                    Self::#variant_name { #(#patterns),* } => {
                        writer.record(stringify!(#variant_name), |__fields| {
                            #(#calls)*
                        });
                    }
                }
            }
            FieldsData::Unnamed(fields) => {
                let bindings = fields
                    .iter()
                    .map(|field| {
                        format_ident!(
                            "__qubit_redact_field_{}",
                            field.index().index,
                            span = field.field().span(),
                        )
                    })
                    .collect::<Vec<_>>();
                let patterns = fields.iter().zip(&bindings).map(|(field, binding)| {
                    let _ = field;
                    quote!(#binding)
                });
                let calls = fields.iter().zip(&bindings).filter_map(|(field, binding)| {
                    let field_name = field.index().index.to_string();
                    let context = variant_field_context(variant.index(), variant_name, &field_name);
                    writer_field_call(
                        field.field(),
                        &field_name,
                        &context,
                        field.attributes().mode(),
                        quote!(#binding),
                        None,
                        runtime,
                    )
                });
                quote! {
                    Self::#variant_name(#(#patterns),*) => {
                        writer.tuple(stringify!(#variant_name), |__fields| {
                            #(#calls)*
                        });
                    }
                }
            }
            FieldsData::Unit => {
                quote! { Self::#variant_name => writer.record(stringify!(#variant_name), |_| {}) }
            }
        }
    });
    quote! {
        match self {
            #(#arms),*
        }
    }
}

/// Generates one structured writer field call.
fn writer_field_call(
    field: &Field,
    field_name: &str,
    _capability_name: &str,
    mode: &FieldMode,
    value: TokenStream,
    key_access: Option<TokenStream>,
    runtime: &Path,
) -> Option<TokenStream> {
    let call = match mode {
        FieldMode::Unmarked => {
            quote! { __fields.unmarked(#field_name, || #value); }
        }
        FieldMode::Level(level) => {
            let level = level.runtime_tokens(runtime);
            quote! { __fields.sensitive_value(#level, #field_name, #value); }
        }
        FieldMode::Nested => quote! { __fields.nested(#field_name, #value); },
        FieldMode::Map => {
            quote! { __fields.map_value(#field_name, #value); }
        }
        FieldMode::MapLevels {
            key,
            value: value_level,
        } => {
            let key = key.as_ref().expect("map key level is required").runtime_tokens(runtime);
            let value_level = value_level
                .as_ref()
                .map(|level| {
                    let level = level.runtime_tokens(runtime);
                    quote!(Some(#level))
                })
                .unwrap_or_else(|| quote!(None));
            quote! { __fields.map_level_values(#field_name, #value, #key, #value_level); }
        }
        FieldMode::KeyedBy(_) => {
            let key = key_access.expect("keyed_by is available only for named fields");
            quote! { __fields.keyed_value(#field_name, #key, #value); }
        }
        FieldMode::Json => {
            quote! { __fields.json_text_value(#field_name, #value); }
        }
        FieldMode::Skip => quote! { __fields.skipped(#field_name, || #value); },
    };
    Some(quote_spanned! {field.span()=> #call })
}

/// Builds a stable diagnostic context name for one enum variant field.
///
/// # Parameters
///
/// * `variant_index` - Zero-based index of the enum variant.
/// * `variant_name` - Rust identifier of the enum variant.
/// * `field_name` - Display name of the field within the variant.
///
/// # Returns
///
/// A context string combining the variant name, index, and field name.
fn variant_field_context(variant_index: u32, variant_name: &Ident, field_name: &str) -> String {
    format!("{variant_name}_{variant_index}_{field_name}")
}
