// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable `Redact` implementation generation.

use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::{DeriveInput, Path, spanned::Spanned};

use crate::{
    container_attributes::ContainerAttributes,
    field_assertion,
    field_mode::FieldMode,
    format_expansion, input_model,
    internal::{ContainerData, FieldsData, NamedField, UnnamedField, VariantData},
    serde_container_attributes::SerdeContainerAttributes,
    serde_expansion, serde_path,
};

/// Expands a struct into its runtime `Redact` implementation.
///
/// # Parameters
///
/// * `input` - Parsed derive input whose generics and fields are preserved.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
///
/// # Returns
///
/// Generated immutable redaction and optional serde implementation tokens.
///
/// # Errors
///
/// Returns a targeted syntax error when container or field controls are
/// invalid or when Serde controls conflict with the input shape.
pub(crate) fn expand(input: &DeriveInput, runtime: &Path) -> syn::Result<TokenStream> {
    let container_attributes = ContainerAttributes::parse(input)?;
    let model = input_model::parse(input, "Redact", container_attributes.serde_enabled())?;
    let serde = container_attributes
        .serde_enabled()
        .then(|| serde_path::resolve(input))
        .transpose()?;
    let serde_container_attributes =
        SerdeContainerAttributes::parse(input, container_attributes.serde_enabled())?;
    let serde_impl = serde_expansion::expand(
        input,
        runtime,
        serde.as_ref(),
        &serde_container_attributes,
        &model,
    )?;
    let (immutable_assertions, format_body) = match &model {
        ContainerData::Struct(fields) => (
            immutable_assertions(&input.ident, fields, runtime),
            format_body(&input.ident, fields),
        ),
        ContainerData::Enum(variants) => (
            enum_immutable_assertions(&input.ident, variants, runtime),
            enum_format_body(&input.ident, variants),
        ),
    };
    let format_impl = format_expansion::expand(input, runtime, &container_attributes);
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #runtime::Redact for #name #type_generics #where_clause {
            fn fmt_redacted(
                &self,
                policy: &#runtime::RedactionPolicy,
                formatter: &mut ::core::fmt::Formatter<'_>,
            ) -> ::core::fmt::Result {
                let _ = policy;
                #(#immutable_assertions)*
                #format_body
            }
        }
        #format_impl
        #serde_impl
    })
}

/// Generates immutable capability assertions for one struct shape.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated implementation.
/// * `fields` - Parsed fields in source order.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// Zero-cost local capability assertions for explicitly redacted fields.
fn immutable_assertions(
    type_name: &syn::Ident,
    fields: &FieldsData<'_>,
    runtime: &Path,
) -> Vec<TokenStream> {
    match fields {
        FieldsData::Named(fields) => fields
            .iter()
            .map(|parsed| {
                let field_name = parsed.identifier().to_string();
                field_assertion::immutable(
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
                field_assertion::immutable(
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

/// Generates the formatter body for one struct shape.
///
/// # Parameters
///
/// * `type_name` - Type name shown in formatter output.
/// * `fields` - Parsed fields in source order.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// A complete formatter expression for named, tuple, or unit structs.
fn format_body(type_name: &syn::Ident, fields: &FieldsData<'_>) -> TokenStream {
    match fields {
        FieldsData::Named(fields) => named_format_body(type_name, fields),
        FieldsData::Unnamed(fields) => unnamed_format_body(type_name, fields),
        FieldsData::Unit => quote! {
            formatter.write_str(stringify!(#type_name))
        },
    }
}

/// Generates the formatter body for named fields.
///
/// # Parameters
///
/// * `type_name` - Type name shown in formatter output.
/// * `fields` - Parsed named fields in source order.
///
/// # Returns
///
/// A `DebugStruct` expression omitting skipped fields.
fn named_format_body(type_name: &syn::Ident, fields: &[NamedField<'_>]) -> TokenStream {
    let field_calls = fields.iter().map(|parsed| {
        let field = parsed.field();
        let identifier = parsed.identifier();
        let attributes = parsed.attributes();
        let field_name = identifier.to_string();
        match attributes.mode() {
            FieldMode::Plain => quote_spanned! {field.span()=>
                .field(#field_name, &self.#identifier)
            },
            FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map => {
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &field_name,
                    immutable_trait_name(attributes.mode()),
                );
                quote_spanned! {field.span()=>
                    .field(#field_name, &#helper(&self.#identifier, policy))
                }
            }
            FieldMode::Skip => TokenStream::new(),
        }
    });
    quote! {
        formatter
            .debug_struct(stringify!(#type_name))
            #(#field_calls)*
            .finish()
    }
}

/// Generates the formatter body for positional fields.
///
/// # Parameters
///
/// * `type_name` - Type name shown in formatter output.
/// * `fields` - Parsed tuple fields in source order.
///
/// # Returns
///
/// A `DebugTuple` expression omitting skipped fields.
fn unnamed_format_body(type_name: &syn::Ident, fields: &[UnnamedField<'_>]) -> TokenStream {
    let field_calls = fields.iter().map(|parsed| {
        let field = parsed.field();
        let index = parsed.index();
        let attributes = parsed.attributes();
        let field_name = index.index.to_string();
        match attributes.mode() {
            FieldMode::Plain => quote_spanned! {field.span()=>
                .field(&self.#index)
            },
            FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map => {
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &field_name,
                    immutable_trait_name(attributes.mode()),
                );
                quote_spanned! {field.span()=>
                    .field(&#helper(&self.#index, policy))
                }
            }
            FieldMode::Skip => TokenStream::new(),
        }
    });
    quote! {
        formatter
            .debug_tuple(stringify!(#type_name))
            #(#field_calls)*
            .finish()
    }
}

/// Returns the immutable capability name for one field mode.
///
/// # Parameters
///
/// * `mode` - Validated field redaction mode.
///
/// # Returns
///
/// The runtime trait name encoded into generated helper identifiers.
const fn immutable_trait_name(mode: &FieldMode) -> &'static str {
    match mode {
        FieldMode::Level(_) => "RedactValue",
        FieldMode::Nested => "Redact",
        FieldMode::Map => "RedactMapValue",
        FieldMode::Plain | FieldMode::Skip => "Unused",
    }
}

/// Generates immutable capability assertions for every enum variant.
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
fn enum_immutable_assertions(
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
                        field_assertion::immutable(
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
                        field_assertion::immutable(
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

/// Generates the formatter match for every enum variant.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variants` - Parsed variants in declaration order.
///
/// # Returns
///
/// A complete match expression preserving each variant's debug shape.
fn enum_format_body(type_name: &syn::Ident, variants: &[VariantData<'_>]) -> TokenStream {
    let arms = variants.iter().map(|variant| {
        let variant_name = &variant.variant().ident;
        match variant.fields() {
            FieldsData::Named(fields) => enum_named_format_arm(type_name, variant_name, fields),
            FieldsData::Unnamed(fields) => enum_unnamed_format_arm(type_name, variant_name, fields),
            FieldsData::Unit => quote! {
                Self::#variant_name => formatter.write_str(stringify!(#variant_name)),
            },
        }
    });
    quote! {
        match self {
            #(#arms)*
        }
    }
}

/// Generates one named enum variant formatter arm.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variant_name` - Variant name shown in formatter output.
/// * `fields` - Parsed named fields in source order.
///
/// # Returns
///
/// A match arm using `DebugStruct` semantics.
fn enum_named_format_arm(
    type_name: &syn::Ident,
    variant_name: &syn::Ident,
    fields: &[NamedField<'_>],
) -> TokenStream {
    let patterns = fields.iter().map(|parsed| {
        let identifier = parsed.identifier();
        if matches!(parsed.attributes().mode(), FieldMode::Skip) {
            quote!(#identifier: _)
        } else {
            quote!(#identifier)
        }
    });
    let field_calls = fields.iter().map(|parsed| {
        let field = parsed.field();
        let identifier = parsed.identifier();
        let mode = parsed.attributes().mode();
        let field_name = identifier.to_string();
        match mode {
            FieldMode::Plain => quote_spanned! {field.span()=>
                .field(#field_name, #identifier)
            },
            FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map => {
                let context = variant_field_context(variant_name, &field_name);
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &context,
                    immutable_trait_name(mode),
                );
                quote_spanned! {field.span()=>
                    .field(#field_name, &#helper(#identifier, policy))
                }
            }
            FieldMode::Skip => TokenStream::new(),
        }
    });
    quote! {
        Self::#variant_name { #(#patterns),* } => formatter
            .debug_struct(stringify!(#variant_name))
            #(#field_calls)*
            .finish(),
    }
}

/// Generates one tuple enum variant formatter arm.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variant_name` - Variant name shown in formatter output.
/// * `fields` - Parsed positional fields in source order.
///
/// # Returns
///
/// A match arm using `DebugTuple` semantics.
fn enum_unnamed_format_arm(
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
        if matches!(parsed.attributes().mode(), FieldMode::Skip) {
            quote!(_)
        } else {
            quote!(#binding)
        }
    });
    let field_calls = fields.iter().zip(&bindings).map(|(parsed, binding)| {
        let field = parsed.field();
        let mode = parsed.attributes().mode();
        match mode {
            FieldMode::Plain => quote_spanned! {field.span()=>
                .field(#binding)
            },
            FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map => {
                let field_name = parsed.index().index.to_string();
                let context = variant_field_context(variant_name, &field_name);
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &context,
                    immutable_trait_name(mode),
                );
                quote_spanned! {field.span()=>
                    .field(&#helper(#binding, policy))
                }
            }
            FieldMode::Skip => TokenStream::new(),
        }
    });
    quote! {
        Self::#variant_name(#(#patterns),*) => formatter
            .debug_tuple(stringify!(#variant_name))
            #(#field_calls)*
            .finish(),
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
