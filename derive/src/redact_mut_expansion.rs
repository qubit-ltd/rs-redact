// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable `RedactMut` implementation generation.

use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::{DeriveInput, Path, spanned::Spanned};

use crate::{
    container_attributes::ContainerAttributes,
    field_assertion,
    field_mode::FieldMode,
    input_model,
    internal::{ContainerData, FieldsData, NamedField, UnnamedField, VariantData},
};

/// Expands a struct into its runtime `RedactMut` implementation.
///
/// # Parameters
///
/// * `input` - Parsed derive input whose generics and fields are preserved.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
///
/// # Returns
///
/// Generated destructive redaction implementation tokens.
///
/// # Errors
///
/// Returns a targeted syntax error when container or field controls are
/// invalid, or when the input is an enum that is not yet supported.
pub(crate) fn expand(input: &DeriveInput, runtime: &Path) -> syn::Result<TokenStream> {
    ContainerAttributes::parse(input)?;
    let model = input_model::parse(input, "RedactMut", false)?;
    let (mutable_assertions, mutations) = match &model {
        ContainerData::Struct(fields) => (
            mutable_assertions(&input.ident, fields, runtime),
            mutations(&input.ident, fields),
        ),
        ContainerData::Enum(variants) => (
            enum_mutable_assertions(&input.ident, variants, runtime),
            enum_mutations(&input.ident, variants),
        ),
    };
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #runtime::RedactMut for #name #type_generics #where_clause {
            fn redact_in_place_with(&mut self, policy: &#runtime::RedactionPolicy) {
                let _ = policy;
                #(#mutable_assertions)*
                #mutations
            }
        }
    })
}

/// Generates mutable capability assertions for one struct shape.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated implementation.
/// * `fields` - Parsed fields in source order.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// Zero-cost local capability assertions for destructively redacted fields.
fn mutable_assertions(
    type_name: &syn::Ident,
    fields: &FieldsData<'_>,
    runtime: &Path,
) -> Vec<TokenStream> {
    match fields {
        FieldsData::Named(fields) => fields
            .iter()
            .map(|parsed| {
                let field_name = parsed.identifier().to_string();
                field_assertion::mutable(
                    type_name,
                    parsed.field(),
                    &field_name,
                    parsed.attributes().mode(),
                    runtime,
                )
            })
            .collect(),
        FieldsData::Unnamed(fields) => fields
            .iter()
            .map(|parsed| {
                let field_name = parsed.index().index.to_string();
                field_assertion::mutable(
                    type_name,
                    parsed.field(),
                    &field_name,
                    parsed.attributes().mode(),
                    runtime,
                )
            })
            .collect(),
        FieldsData::Unit => Vec::new(),
    }
}

/// Generates destructive calls for one struct shape.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated implementation.
/// * `fields` - Parsed fields in source order.
///
/// # Returns
///
/// Mutation statements for fields with destructive redaction modes.
fn mutations(type_name: &syn::Ident, fields: &FieldsData<'_>) -> TokenStream {
    match fields {
        FieldsData::Named(fields) => {
            let mutations = named_mutations(type_name, fields);
            quote!(#(#mutations)*)
        }
        FieldsData::Unnamed(fields) => {
            let mutations = unnamed_mutations(type_name, fields);
            quote!(#(#mutations)*)
        }
        FieldsData::Unit => TokenStream::new(),
    }
}

/// Generates destructive calls for named fields.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated implementation.
/// * `fields` - Parsed named fields in source order.
///
/// # Returns
///
/// Mutation statements for fields with destructive redaction modes.
fn named_mutations(type_name: &syn::Ident, fields: &[NamedField<'_>]) -> Vec<TokenStream> {
    fields
        .iter()
        .filter_map(|parsed| {
            let field = parsed.field();
            let identifier = parsed.identifier();
            let mode = parsed.attributes().mode();
            if matches!(mode, FieldMode::Plain | FieldMode::Skip) {
                return None;
            }
            let field_name = identifier.to_string();
            let helper = field_assertion::helper_name(
                type_name,
                field,
                &field_name,
                mutable_trait_name(mode),
            );
            Some(quote_spanned! {field.span()=>
                #helper(&mut self.#identifier, policy);
            })
        })
        .collect()
}

/// Generates destructive calls for positional fields.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated implementation.
/// * `fields` - Parsed tuple fields in source order.
///
/// # Returns
///
/// Mutation statements for fields with destructive redaction modes.
fn unnamed_mutations(type_name: &syn::Ident, fields: &[UnnamedField<'_>]) -> Vec<TokenStream> {
    fields
        .iter()
        .filter_map(|parsed| {
            let field = parsed.field();
            let index = parsed.index();
            let mode = parsed.attributes().mode();
            if matches!(mode, FieldMode::Plain | FieldMode::Skip) {
                return None;
            }
            let field_name = index.index.to_string();
            let helper = field_assertion::helper_name(
                type_name,
                field,
                &field_name,
                mutable_trait_name(mode),
            );
            Some(quote_spanned! {field.span()=>
                #helper(&mut self.#index, policy);
            })
        })
        .collect()
}

/// Returns the destructive capability name for one field mode.
///
/// # Parameters
///
/// * `mode` - Validated field redaction mode.
///
/// # Returns
///
/// The runtime trait name encoded into generated helper identifiers.
const fn mutable_trait_name(mode: &FieldMode) -> &'static str {
    match mode {
        FieldMode::Level(_) => "RedactValueMut",
        FieldMode::Nested => "RedactMut",
        FieldMode::Map => "RedactMapValueMut",
        FieldMode::Plain | FieldMode::Skip => "Unused",
    }
}

/// Generates mutable capability assertions for every enum variant.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variants` - Parsed variants in declaration order.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// Zero-cost local capability assertions with variant-qualified names.
fn enum_mutable_assertions(
    type_name: &syn::Ident,
    variants: &[VariantData<'_>],
    runtime: &Path,
) -> Vec<TokenStream> {
    variants
        .iter()
        .flat_map(|variant| {
            let variant_name = &variant.variant().ident;
            match variant.fields() {
                FieldsData::Named(fields) => fields
                    .iter()
                    .map(|parsed| {
                        let field_name = parsed.identifier().to_string();
                        let context = variant_field_context(variant_name, &field_name);
                        field_assertion::mutable(
                            type_name,
                            parsed.field(),
                            &context,
                            parsed.attributes().mode(),
                            runtime,
                        )
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unnamed(fields) => fields
                    .iter()
                    .map(|parsed| {
                        let field_name = parsed.index().index.to_string();
                        let context = variant_field_context(variant_name, &field_name);
                        field_assertion::mutable(
                            type_name,
                            parsed.field(),
                            &context,
                            parsed.attributes().mode(),
                            runtime,
                        )
                    })
                    .collect(),
                FieldsData::Unit => Vec::new(),
            }
        })
        .collect()
}

/// Generates the destructive match for every enum variant.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variants` - Parsed variants in declaration order.
///
/// # Returns
///
/// A complete match expression that mutates only the active variant.
fn enum_mutations(type_name: &syn::Ident, variants: &[VariantData<'_>]) -> TokenStream {
    let arms = variants.iter().map(|variant| {
        let variant_name = &variant.variant().ident;
        match variant.fields() {
            FieldsData::Named(fields) => enum_named_mutation_arm(type_name, variant_name, fields),
            FieldsData::Unnamed(fields) => {
                enum_unnamed_mutation_arm(type_name, variant_name, fields)
            }
            FieldsData::Unit => quote!(Self::#variant_name => {}),
        }
    });
    quote! {
        match self {
            #(#arms),*
        }
    }
}

/// Generates one named enum variant mutation arm.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variant_name` - Variant owning the fields.
/// * `fields` - Parsed named fields in source order.
///
/// # Returns
///
/// A match arm mutating explicitly selected bindings.
fn enum_named_mutation_arm(
    type_name: &syn::Ident,
    variant_name: &syn::Ident,
    fields: &[NamedField<'_>],
) -> TokenStream {
    let patterns = fields.iter().map(|parsed| {
        let identifier = parsed.identifier();
        if matches!(
            parsed.attributes().mode(),
            FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map,
        ) {
            quote!(#identifier)
        } else {
            quote!(#identifier: _)
        }
    });
    let mutations = fields.iter().filter_map(|parsed| {
        let field = parsed.field();
        let identifier = parsed.identifier();
        let mode = parsed.attributes().mode();
        if matches!(mode, FieldMode::Plain | FieldMode::Skip) {
            return None;
        }
        let field_name = identifier.to_string();
        let context = variant_field_context(variant_name, &field_name);
        let helper =
            field_assertion::helper_name(type_name, field, &context, mutable_trait_name(mode));
        Some(quote_spanned! {field.span()=>
            #helper(#identifier, policy);
        })
    });
    quote! {
        Self::#variant_name { #(#patterns),* } => {
            #(#mutations)*
        }
    }
}

/// Generates one tuple enum variant mutation arm.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variant_name` - Variant owning the fields.
/// * `fields` - Parsed positional fields in source order.
///
/// # Returns
///
/// A match arm mutating explicitly selected positional bindings.
fn enum_unnamed_mutation_arm(
    type_name: &syn::Ident,
    variant_name: &syn::Ident,
    fields: &[UnnamedField<'_>],
) -> TokenStream {
    let bindings = fields
        .iter()
        .map(|parsed| {
            format_ident!(
                "__qubit_redact_field_{}",
                parsed.index().index,
                span = parsed.field().span(),
            )
        })
        .collect::<Vec<_>>();
    let patterns = fields.iter().zip(&bindings).map(|(parsed, binding)| {
        if matches!(
            parsed.attributes().mode(),
            FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map,
        ) {
            quote!(#binding)
        } else {
            quote!(_)
        }
    });
    let mutations = fields
        .iter()
        .zip(&bindings)
        .filter_map(|(parsed, binding)| {
            let field = parsed.field();
            let mode = parsed.attributes().mode();
            if matches!(mode, FieldMode::Plain | FieldMode::Skip) {
                return None;
            }
            let field_name = parsed.index().index.to_string();
            let context = variant_field_context(variant_name, &field_name);
            let helper =
                field_assertion::helper_name(type_name, field, &context, mutable_trait_name(mode));
            Some(quote_spanned! {field.span()=>
                #helper(#binding, policy);
            })
        });
    quote! {
        Self::#variant_name(#(#patterns),*) => {
            #(#mutations)*
        }
    }
}

/// Creates a helper-name fragment unique within one enum.
///
/// # Parameters
///
/// * `variant_name` - Owning enum variant.
/// * `field_name` - Field identifier or positional index.
///
/// # Returns
///
/// A stable variant-qualified field context.
fn variant_field_context(variant_name: &syn::Ident, field_name: &str) -> String {
    format!("{variant_name}_{field_name}")
}
