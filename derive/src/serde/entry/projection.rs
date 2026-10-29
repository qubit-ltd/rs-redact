// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed projection declarations and construction expressions.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use syn::DeriveInput;
use syn::Field;
use syn::Generics;
use syn::Ident;
use syn::Lifetime;
use syn::ext::IdentExt;
use syn::spanned::Spanned;

use super::super::recursive_projection;
use super::super::source_function_path::SourceTypeContext;
use super::super::source_function_path::source_function_path;
use crate::attributes::SerdeAttributes;
use crate::model::ContainerData;
use crate::model::FieldMode;
use crate::model::FieldsData;

/// Declares the hidden borrowed projection type.
///
/// # Parameters
///
/// * `input` - Source type supplying visibility, generic context, and marker
///   type.
/// * `projection` - Generated projection type identifier.
/// * `lifetime` - Lifetime used by each borrowed field.
/// * `parameters` - Generated type parameters in source-field order.
/// * `model` - Validated source shape.
/// * `generics` - Source and generated projection parameters, including bounds.
/// * `marker` - Fresh member name reserved for the projection lifetime marker.
///
/// # Returns
///
/// A hidden struct or enum declaration with borrowed fields and a lifetime
/// marker.
///
/// # Panics
///
/// Panics if an enum field has no corresponding generated type parameter.
#[must_use]
pub(super) fn projection_declaration(
    input: &DeriveInput,
    projection: &Ident,
    lifetime: &Lifetime,
    parameters: &[Ident],
    model: &ContainerData<'_>,
    generics: &Generics,
    marker: &Ident,
) -> TokenStream {
    let source = &input.ident;
    let (_, source_arguments, _) = input.generics.split_for_impl();
    let (declaration_generics, _, declaration_where_clause) = generics.split_for_impl();
    match model {
        ContainerData::Struct(fields) => {
            let members = match fields {
                FieldsData::Named(fields) => fields
                    .iter()
                    .zip(parameters)
                    .map(|(field, parameter)| {
                        let name = field.identifier();
                        let ty = projection_member_type(
                            input,
                            field.field(),
                            field.attributes().mode(),
                            field.serde_attributes(),
                            parameter,
                            lifetime,
                        );
                        quote!(#name: #ty)
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unnamed(fields) => fields
                    .iter()
                    .zip(parameters)
                    .map(|(field, parameter)| {
                        let name = format_ident!("__qubit_redact_field_{}", field.index().index);
                        let ty = projection_member_type(
                            input,
                            field.field(),
                            field.attributes().mode(),
                            field.serde_attributes(),
                            parameter,
                            lifetime,
                        );
                        quote!(#name: #ty)
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unit => Vec::new(),
            };
            quote! {
                #[doc(hidden)]
                #[derive(Clone, Copy)]
                struct #projection #declaration_generics #declaration_where_clause {
                    #marker: ::core::marker::PhantomData<(&#lifetime #source #source_arguments, #(&#lifetime #parameters),*)>,
                    #(#members),*
                }
            }
        }
        ContainerData::Enum(variants) => {
            let mut offset = 0usize;
            let declarations = variants.iter().map(|variant| {
                let name = &variant.variant().ident;
                let declaration = match variant.fields() {
                    FieldsData::Named(fields) => {
                        let start = offset;
                        let members = fields.iter().enumerate().map(|(index, field)| {
                            let name = field.identifier();
                            let parameter = projection_member_type(
                                input,
                                field.field(),
                                field.attributes().mode(),
                                field.serde_attributes(),
                                &parameters[start + index],
                                lifetime,
                            );
                            quote!(#name: #parameter)
                        });
                        offset += fields.len();
                        quote!({ #(#members),* })
                    }
                    FieldsData::Unnamed(fields) => {
                        let start = offset;
                        let members = fields.iter().enumerate().map(|(index, field)| {
                            let parameter = projection_member_type(
                                input,
                                field.field(),
                                field.attributes().mode(),
                                field.serde_attributes(),
                                &parameters[start + index],
                                lifetime,
                            );
                            quote!(#parameter)
                        });
                        offset += fields.len();
                        quote!(( #(#members),* ))
                    }
                    FieldsData::Unit => TokenStream::new(),
                };
                quote!(#name #declaration)
            });
            quote! {
                #[doc(hidden)]
                #[derive(Clone, Copy)]
                enum #projection #declaration_generics #declaration_where_clause {
                    #(#declarations,)*
                    #marker(::core::marker::PhantomData<(&#lifetime #source #source_arguments, #(&#lifetime #parameters),*)>)
                }
            }
        }
    }
}

/// Selects the field type visible to predicates and custom serializers.
///
/// # Parameters
///
/// * `field` - Source field retaining its concrete generic type expression.
/// * `attributes` - Serialization controls that may call a type-specific
///   function.
/// * `parameter` - Independent projection parameter for ordinary field
///   capabilities.
///
/// # Returns
///
/// The source type for fields with predicates or adapters, otherwise the
/// generated parameter that keeps serialization bounds conditional.
#[must_use]
pub(in crate::serde::entry) fn projection_field_type(
    field: &Field,
    attributes: &SerdeAttributes,
    parameter: &Ident,
) -> TokenStream {
    if attributes.serialize_with().is_some() {
        let ty = &field.ty;
        quote!(#ty)
    } else {
        quote!(#parameter)
    }
}

/// Builds one borrowed projection member, retaining a callable Serde predicate
/// without making the concrete source field type part of its declaration.
fn projection_member_type(
    input: &DeriveInput,
    field: &Field,
    mode: &FieldMode,
    attributes: &SerdeAttributes,
    parameter: &Ident,
    lifetime: &Lifetime,
) -> TokenStream {
    let ty = if matches!(mode, FieldMode::Nested) && recursive_projection::shape(input, &field.ty).is_some() {
        recursive_projection::concrete_field_type(input, &field.ty)
    } else {
        projection_field_type(field, attributes, parameter)
    };
    if projection_uses_saved_predicate(attributes) {
        quote!((& #lifetime #ty, fn(&#ty) -> bool))
    } else {
        quote!(& #lifetime #ty)
    }
}

/// Returns whether a field predicate is stored in the borrowed projection.
fn projection_uses_saved_predicate(attributes: &SerdeAttributes) -> bool {
    !attributes.skip() && attributes.skip_serializing_if().is_some() && attributes.serialize_with().is_none()
}

/// Builds a borrowed projection from the source value.
///
/// # Parameters
///
/// * `source_context` - Source identity for enum patterns and saved predicates.
/// * `projection` - Generated projection type identifier.
/// * `model` - Validated source shape and source fields.
/// * `marker` - Fresh member name used by the projection declaration.
///
/// # Returns
///
/// An expression borrowing the struct fields or matching the selected enum
/// variant.
#[must_use]
pub(super) fn projection_constructor_for(
    source_context: &SourceTypeContext<'_>,
    projection: &Ident,
    model: &ContainerData<'_>,
    marker: &Ident,
    source: TokenStream,
) -> TokenStream {
    let name = source_context.ident;
    match model {
        ContainerData::Struct(fields) => {
            let members = match fields {
                FieldsData::Named(fields) => fields
                    .iter()
                    .map(|field| {
                        let name = field.identifier();
                        let value =
                            projection_member_value(source_context, field.serde_attributes(), quote!(&#source.#name));
                        quote!(#name: #value)
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unnamed(fields) => fields
                    .iter()
                    .map(|field| {
                        let index = field.index();
                        let name = format_ident!("__qubit_redact_field_{}", index.index);
                        let value =
                            projection_member_value(source_context, field.serde_attributes(), quote!(&#source.#index));
                        quote!(#name: #value)
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unit => Vec::new(),
            };
            quote!(#projection { #marker: ::core::marker::PhantomData, #(#members),* })
        }
        ContainerData::Enum(variants) => {
            if variants.is_empty() {
                return quote!(match *#source {});
            }
            let arms = variants.iter().map(|variant| {
                let variant_name = &variant.variant().ident;
                match variant.fields() {
                    FieldsData::Named(fields) => {
                        let names = fields.iter().map(|field| field.identifier()).collect::<Vec<_>>();
                        let values = fields.iter().map(|field| {
                            let name = field.identifier();
                            let value =
                                projection_member_value(source_context, field.serde_attributes(), quote!(#name));
                            quote!(#name: #value)
                        });
                        quote!(#name::#variant_name { #(#names),* } => #projection::#variant_name { #(#values),* })
                    }
                    FieldsData::Unnamed(fields) => {
                        let names = fields
                            .iter()
                            .enumerate()
                            .map(|(index, field)| {
                                format_ident!("__qubit_redact_projection_{index}", span = field.field().span())
                            })
                            .collect::<Vec<_>>();
                        let values = fields.iter().zip(&names).map(|(field, name)| {
                            projection_member_value(source_context, field.serde_attributes(), quote!(#name))
                        });
                        quote!(#name::#variant_name(#(#names),*) => #projection::#variant_name(#(#values),*))
                    }
                    FieldsData::Unit => quote!(#name::#variant_name => #projection::#variant_name),
                }
            });
            quote!(match #source { #(#arms),* })
        }
    }
}

/// Builds a field value and rebinds a saved predicate to its source type.
fn projection_member_value(
    source_context: &SourceTypeContext<'_>,
    attributes: &SerdeAttributes,
    raw: TokenStream,
) -> TokenStream {
    if projection_uses_saved_predicate(attributes) {
        let predicate = attributes.skip_serializing_if().expect("saved predicate was checked");
        let predicate = source_function_path(source_context, predicate);
        quote!((#raw, #predicate))
    } else {
        raw
    }
}
/// Chooses a projection marker distinct from source field or variant names.
///
/// # Parameters
///
/// * `model` - Source members occupying the generated projection namespace.
///
/// # Returns
///
/// A fresh marker identifier, comparing raw and ordinary spellings equally.
///
/// # Panics
///
/// Panics only if every generated numeric suffix is occupied.
#[must_use]
pub(super) fn projection_marker(model: &ContainerData<'_>) -> Ident {
    let (base, occupied) = match model {
        ContainerData::Struct(FieldsData::Named(fields)) => (
            "__qubit_redact_lifetime",
            fields
                .iter()
                .map(|field| field.identifier().unraw().to_string())
                .collect::<Vec<_>>(),
        ),
        ContainerData::Struct(_) => ("__qubit_redact_lifetime", Vec::new()),
        ContainerData::Enum(variants) => (
            "__QubitRedactLifetime",
            variants
                .iter()
                .map(|variant| variant.variant().ident.unraw().to_string())
                .collect(),
        ),
    };
    if !occupied.iter().any(|name| name == base) {
        return format_ident!("{base}");
    }
    (0..)
        .map(|index| format_ident!("{base}_{index}"))
        .find(|candidate| !occupied.contains(&candidate.to_string()))
        .expect("a finite source has an unused projection marker name")
}
