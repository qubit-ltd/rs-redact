// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redacted Serde implementation generation.

use proc_macro2::TokenStream;
use quote::{
    format_ident,
    quote,
    quote_spanned,
};
use syn::{
    DeriveInput,
    Path,
    spanned::Spanned,
};

use crate::{
    field_assertion,
    field_mode::FieldMode,
    internal::{
        ContainerData,
        FieldsData,
        NamedField,
        UnnamedField,
        VariantData,
    },
    serde_container_attributes::SerdeContainerAttributes,
    serde_enum_representation::SerdeEnumRepresentation,
};

/// Generates optional redacted serialization for every supported input shape.
///
/// # Parameters
///
/// * `input` - Derive input whose name and generics are preserved.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved direct Serde dependency when integration is enabled.
/// * `container_attributes` - Validated Serde container controls.
/// * `model` - Shared parsed struct or enum model.
///
/// # Returns
///
/// A `RedactSerialize` implementation when integration is enabled, or an
/// empty token stream otherwise.
///
/// # Errors
///
/// Returns a targeted error for a structurally invalid enum representation.
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
    serde: Option<&Path>,
    container_attributes: &SerdeContainerAttributes,
    model: &ContainerData<'_>,
) -> syn::Result<TokenStream> {
    let Some(serde) = serde else {
        return Ok(TokenStream::new());
    };

    let serialization_assertions =
        serialization_assertions(&input.ident, model, runtime);
    let body = match model {
        ContainerData::Struct(fields) => struct_body(
            &input.ident,
            fields,
            runtime,
            serde,
            container_attributes,
        ),
        ContainerData::Enum(variants) => enum_body(
            &input.ident,
            variants,
            runtime,
            serde,
            container_attributes,
        )?,
    };
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) =
        input.generics.split_for_impl();

    Ok(quote! {
        #runtime::__qubit_redact_serde! {
            impl #impl_generics #runtime::__private::RedactSerialize
                for #name #type_generics #where_clause
            {
                fn serialize_redacted<__QubitRedactSerializer>(
                    &self,
                    policy: &#runtime::RedactionPolicy,
                    serializer: __QubitRedactSerializer,
                ) -> ::core::result::Result<
                    __QubitRedactSerializer::Ok,
                    __QubitRedactSerializer::Error,
                >
                where
                    __QubitRedactSerializer: #serde::Serializer,
                {
                    #(#serialization_assertions)*
                    #body
                }
            }
        }
    })
}

/// Generates serialization capability assertions for the shared model.
///
/// # Parameters
///
/// * `type_name` - Type receiving the hidden implementation.
/// * `model` - Parsed struct or enum model.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// Local helper functions for nested and map fields.
fn serialization_assertions(
    type_name: &syn::Ident,
    model: &ContainerData<'_>,
    runtime: &Path,
) -> Vec<TokenStream> {
    match model {
        ContainerData::Struct(fields) => {
            fields_serialization_assertions(type_name, fields, None, runtime)
        }
        ContainerData::Enum(variants) => variants
            .iter()
            .flat_map(|variant| {
                fields_serialization_assertions(
                    type_name,
                    variant.fields(),
                    Some(&variant.variant().ident),
                    runtime,
                )
            })
            .collect(),
    }
}

/// Generates serialization assertions for one field collection.
fn fields_serialization_assertions(
    type_name: &syn::Ident,
    fields: &FieldsData<'_>,
    variant_name: Option<&syn::Ident>,
    runtime: &Path,
) -> Vec<TokenStream> {
    match fields {
        FieldsData::Named(fields) => fields
            .iter()
            .map(|parsed| {
                let field_name = parsed.identifier().to_string();
                let context = field_context(variant_name, &field_name);
                field_assertion::serialization(
                    type_name,
                    parsed.field(),
                    &context,
                    parsed.attributes().mode(),
                    runtime,
                )
            })
            .collect(),
        FieldsData::Unnamed(fields) => fields
            .iter()
            .map(|parsed| {
                let field_name = parsed.index().index.to_string();
                let context = field_context(variant_name, &field_name);
                field_assertion::serialization(
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
}

/// Generates redacted serialization for one struct shape.
fn struct_body(
    type_name: &syn::Ident,
    fields: &FieldsData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> TokenStream {
    match fields {
        FieldsData::Named(fields) => named_struct_body(
            type_name,
            fields,
            runtime,
            serde,
            container_attributes,
        ),
        FieldsData::Unnamed(fields) if fields.len() == 1 => {
            newtype_struct_body(
                type_name,
                &fields[0],
                runtime,
                serde,
                container_attributes,
            )
        }
        FieldsData::Unnamed(fields) => tuple_struct_body(
            type_name,
            fields,
            runtime,
            serde,
            container_attributes,
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

/// Generates named-struct serialization.
fn named_struct_body(
    type_name: &syn::Ident,
    fields: &[NamedField<'_>],
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> TokenStream {
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut serialized_names = Vec::new();
    let mut carriers = Vec::new();

    for (position, parsed) in fields.iter().enumerate() {
        if field_is_skipped(
            parsed.attributes().mode(),
            parsed.serde_attributes(),
        ) {
            continue;
        }
        let field = parsed.field();
        let identifier = parsed.identifier();
        let raw_name = raw_identifier(identifier);
        let serialized_name = parsed.serde_attributes().rename().map_or_else(
            || container_attributes.rename_struct_field(&raw_name),
            str::to_owned,
        );
        let raw = quote_spanned!(field.span()=> &self.#identifier);
        let context = field_context(None, &raw_name);
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let value = serialized_carrier(
            type_name,
            field,
            &context,
            parsed.attributes().mode(),
            runtime,
            raw.clone(),
        );
        let condition = serialization_condition(parsed.serde_attributes(), raw);
        setups.push(quote_spanned! {field.span()=>
            let #carrier = if #condition {
                ::core::option::Option::Some(#value)
            } else {
                ::core::option::Option::None
            };
        });
        conditions.push(quote!(#carrier.is_some()));
        serialized_names.push(serialized_name);
        carriers.push(carrier);
    }

    let count_conditions = &conditions;
    let serialized_name = container_attributes.name();
    let calls = conditions.iter().zip(&serialized_names).zip(&carriers).map(
        |((_condition, field_name), carrier)| {
            quote! {
                if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #field_name,
                        carrier,
                    )?;
                }
            }
        },
    );
    quote! {
        #(#setups)*
        let mut field_count = 0usize;
        #(
            if #count_conditions {
                field_count += 1;
            }
        )*
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
fn newtype_struct_body(
    type_name: &syn::Ident,
    parsed: &UnnamedField<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> TokenStream {
    let serialized_name = container_attributes.name();
    if field_is_skipped(parsed.attributes().mode(), parsed.serde_attributes()) {
        return quote! {
            #serde::Serializer::serialize_unit_struct(serializer, #serialized_name)
        };
    }
    let field = parsed.field();
    let index = parsed.index();
    let raw = quote_spanned!(field.span()=> &self.#index);
    let context = field_context(None, &index.index.to_string());
    let value = serialized_carrier(
        type_name,
        field,
        &context,
        parsed.attributes().mode(),
        runtime,
        raw.clone(),
    );
    let condition = serialization_condition(parsed.serde_attributes(), raw);
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

/// Generates tuple-struct serialization.
fn tuple_struct_body(
    type_name: &syn::Ident,
    fields: &[UnnamedField<'_>],
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> TokenStream {
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut carriers = Vec::new();
    for (position, parsed) in fields.iter().enumerate() {
        if field_is_skipped(
            parsed.attributes().mode(),
            parsed.serde_attributes(),
        ) {
            continue;
        }
        let field = parsed.field();
        let index = parsed.index();
        let raw = quote_spanned!(field.span()=> &self.#index);
        let context = field_context(None, &index.index.to_string());
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let value = serialized_carrier(
            type_name,
            field,
            &context,
            parsed.attributes().mode(),
            runtime,
            raw.clone(),
        );
        let condition = serialization_condition(parsed.serde_attributes(), raw);
        setups.push(quote_spanned! {field.span()=>
            let #carrier = if #condition {
                ::core::option::Option::Some(#value)
            } else {
                ::core::option::Option::None
            };
        });
        conditions.push(quote!(#carrier.is_some()));
        carriers.push(carrier);
    }
    let count_conditions = &conditions;
    let serialized_name = container_attributes.name();
    let calls = conditions
        .iter()
        .zip(&carriers)
        .map(|(_condition, carrier)| {
            quote! {
                if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                    #serde::ser::SerializeTupleStruct::serialize_field(
                        &mut state,
                        carrier,
                    )?;
                }
            }
        });
    quote! {
        #(#setups)*
        let mut field_count = 0usize;
        #(
            if #count_conditions {
                field_count += 1;
            }
        )*
        let mut state = #serde::Serializer::serialize_tuple_struct(
            serializer,
            #serialized_name,
            field_count,
        )?;
        #(#calls)*
        #serde::ser::SerializeTupleStruct::end(state)
    }
}

/// Returns whether a field is omitted by redaction or Serde controls.
fn field_is_skipped(
    mode: &FieldMode,
    serde_attributes: &crate::serde_attributes::SerdeAttributes,
) -> bool {
    matches!(mode, FieldMode::Skip) || serde_attributes.skip()
}

/// Generates the condition deciding whether one field is serialized.
fn serialization_condition(
    serde_attributes: &crate::serde_attributes::SerdeAttributes,
    raw: TokenStream,
) -> TokenStream {
    serde_attributes
        .skip_serializing_if()
        .map_or_else(|| quote!(true), |predicate| quote!(!(#predicate)(#raw)))
}

/// Generates one serializable raw or redacted carrier expression.
fn serialized_carrier(
    type_name: &syn::Ident,
    field: &syn::Field,
    context: &str,
    mode: &FieldMode,
    runtime: &Path,
    raw: TokenStream,
) -> TokenStream {
    match mode {
        FieldMode::Plain => raw,
        FieldMode::Level(sensitivity) => {
            let level = sensitivity.runtime_tokens(runtime);
            quote_spanned! {field.span()=>
                #runtime::RedactValue::redact_value(
                    #raw,
                    #level,
                    policy.masking(),
                )
            }
        }
        FieldMode::Nested => {
            let helper = field_assertion::helper_name(
                type_name,
                field,
                context,
                "RedactSerialize",
            );
            quote_spanned!(field.span()=> #helper(#raw, policy))
        }
        FieldMode::Map => {
            let helper = field_assertion::helper_name(
                type_name,
                field,
                context,
                "RedactMapSerialize",
            );
            quote_spanned!(field.span()=> #helper(#raw, policy))
        }
        FieldMode::Skip => TokenStream::new(),
    }
}

/// Returns an identifier without Rust's raw prefix.
fn raw_identifier(identifier: &syn::Ident) -> String {
    identifier
        .to_string()
        .strip_prefix("r#")
        .map_or_else(|| identifier.to_string(), str::to_owned)
}

/// Creates a helper-name context unique within an enum.
fn field_context(
    variant_name: Option<&syn::Ident>,
    field_name: &str,
) -> String {
    variant_name.map_or_else(
        || field_name.to_owned(),
        |variant| format!("{variant}_{field_name}"),
    )
}

/// Generates redacted serialization for an enum representation.
fn enum_body(
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
                    external_variant_arm(
                        type_name,
                        variant,
                        runtime,
                        serde,
                        container_attributes,
                    )
                }
                SerdeEnumRepresentation::InternallyTagged { tag } => {
                    internal_variant_arm(
                        type_name,
                        variant,
                        runtime,
                        serde,
                        container_attributes,
                        tag,
                    )
                }
                SerdeEnumRepresentation::AdjacentlyTagged { tag, content } => {
                    adjacent_variant_arm(
                        type_name,
                        variant,
                        runtime,
                        serde,
                        container_attributes,
                        tag,
                        content,
                    )
                }
                SerdeEnumRepresentation::Untagged => untagged_variant_arm(
                    type_name,
                    variant,
                    runtime,
                    serde,
                    container_attributes,
                ),
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
fn skipped_variant_arm(variant: &VariantData<'_>, serde: &Path) -> TokenStream {
    let variant_name = &variant.variant().ident;
    let pattern = wildcard_variant_pattern(variant);
    let message =
        format!("cannot serialize skipped redacted variant `{variant_name}`",);
    quote! {
        Self::#variant_name #pattern => ::core::result::Result::Err(
            <__QubitRedactSerializer::Error as #serde::ser::Error>::custom(#message),
        )
    }
}

/// Generates a wildcard suffix for one variant pattern.
fn wildcard_variant_pattern(variant: &VariantData<'_>) -> TokenStream {
    match variant.fields() {
        FieldsData::Named(_) => quote!({ .. }),
        FieldsData::Unnamed(_) => quote!((..)),
        FieldsData::Unit => TokenStream::new(),
    }
}

/// Generates one externally tagged variant arm.
fn external_variant_arm(
    type_name: &syn::Ident,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> syn::Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let enum_name = container_attributes.name();
    let variant_index = variant.index();
    let arm = match variant.fields() {
        FieldsData::Named(fields) => {
            let (pattern, setups, conditions, names, carriers) =
                enum_named_parts(
                    type_name,
                    rust_name,
                    fields,
                    runtime,
                    container_attributes,
                    variant,
                );
            let count_conditions = &conditions;
            let calls = conditions.iter().zip(&names).zip(&carriers).map(
                |((_condition, field_name), carrier)| {
                    quote! {
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::ser::SerializeStructVariant::serialize_field(
                                &mut state,
                                #field_name,
                                carrier,
                            )?;
                        }
                    }
                },
            );
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    let mut field_count = 0usize;
                    #(
                        if #count_conditions {
                            field_count += 1;
                        }
                    )*
                    let mut state = #serde::Serializer::serialize_struct_variant(
                        serializer,
                        #enum_name,
                        #variant_index,
                        #variant_name,
                        field_count,
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeStructVariant::end(state)
                }
            }
        }
        FieldsData::Unnamed(fields) if fields.len() == 1 => {
            let (pattern, setups, _conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, fields, runtime);
            if carriers.is_empty() {
                quote! {
                    Self::#rust_name #pattern => #serde::Serializer::serialize_unit_variant(
                        serializer,
                        #enum_name,
                        #variant_index,
                        #variant_name,
                    )
                }
            } else {
                let carrier = &carriers[0];
                quote! {
                    Self::#rust_name #pattern => {
                        #(#setups)*
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::Serializer::serialize_newtype_variant(
                                serializer,
                                #enum_name,
                                #variant_index,
                                #variant_name,
                                carrier,
                            )
                        } else {
                            #serde::Serializer::serialize_unit_variant(
                                serializer,
                                #enum_name,
                                #variant_index,
                                #variant_name,
                            )
                        }
                    }
                }
            }
        }
        FieldsData::Unnamed(fields) => {
            let (pattern, setups, conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, fields, runtime);
            let count_conditions = &conditions;
            let calls = conditions
                .iter()
                .zip(&carriers)
                .map(|(_condition, carrier)| {
                    quote! {
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::ser::SerializeTupleVariant::serialize_field(
                                &mut state,
                                carrier,
                            )?;
                        }
                    }
                });
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    let mut field_count = 0usize;
                    #(
                        if #count_conditions {
                            field_count += 1;
                        }
                    )*
                    let mut state = #serde::Serializer::serialize_tuple_variant(
                        serializer,
                        #enum_name,
                        #variant_index,
                        #variant_name,
                        field_count,
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeTupleVariant::end(state)
                }
            }
        }
        FieldsData::Unit => quote! {
            Self::#rust_name => #serde::Serializer::serialize_unit_variant(
                serializer,
                #enum_name,
                #variant_index,
                #variant_name,
            )
        },
    };
    Ok(arm)
}

/// Generates one internally tagged variant arm.
fn internal_variant_arm(
    type_name: &syn::Ident,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    tag: &str,
) -> syn::Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let enum_name = container_attributes.name();
    match variant.fields() {
        FieldsData::Named(fields) => {
            let (pattern, setups, conditions, names, carriers) =
                enum_named_parts(
                    type_name,
                    rust_name,
                    fields,
                    runtime,
                    container_attributes,
                    variant,
                );
            if let Some((field, _)) =
                fields.iter().zip(&names).find(|(_, name)| *name == tag)
            {
                return Err(syn::Error::new_spanned(
                    field.field(),
                    format!(
                        "Redact serde for `{type_name}` variant `{rust_name}` has field `{tag}` conflicting with the internal tag",
                    ),
                ));
            }
            let count_conditions = &conditions;
            let calls = conditions.iter().zip(&names).zip(&carriers).map(
                |((_condition, field_name), carrier)| {
                    quote! {
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::ser::SerializeStruct::serialize_field(
                                &mut state,
                                #field_name,
                                carrier,
                            )?;
                        }
                    }
                },
            );
            Ok(quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    let mut field_count = 1usize;
                    #(
                        if #count_conditions {
                            field_count += 1;
                        }
                    )*
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #enum_name,
                        field_count,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #tag,
                        #variant_name,
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeStruct::end(state)
                }
            })
        }
        FieldsData::Unnamed(fields) if fields.len() == 1 => {
            let (pattern, setups, _conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, fields, runtime);
            if carriers.is_empty() {
                Ok(quote! {
                    Self::#rust_name #pattern => {
                        let mut state = #serde::Serializer::serialize_struct(
                            serializer,
                            #enum_name,
                            1,
                        )?;
                        #serde::ser::SerializeStruct::serialize_field(
                            &mut state,
                            #tag,
                            #variant_name,
                        )?;
                        #serde::ser::SerializeStruct::end(state)
                    }
                })
            } else {
                let carrier = &carriers[0];
                Ok(quote! {
                    Self::#rust_name #pattern => {
                        #(#setups)*
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #runtime::__private::serialize_internally_tagged(
                                serializer,
                                #enum_name,
                                stringify!(#rust_name),
                                #tag,
                                #variant_name,
                                carrier,
                            )
                        } else {
                            let mut state = #serde::Serializer::serialize_struct(
                                serializer,
                                #enum_name,
                                1,
                            )?;
                            #serde::ser::SerializeStruct::serialize_field(
                                &mut state,
                                #tag,
                                #variant_name,
                            )?;
                            #serde::ser::SerializeStruct::end(state)
                        }
                    }
                })
            }
        }
        FieldsData::Unnamed(_) => Err(syn::Error::new_spanned(
            variant.variant(),
            format!(
                "Redact serde for internally tagged `{type_name}` does not allow tuple variants",
            ),
        )),
        FieldsData::Unit => Ok(quote! {
            Self::#rust_name => {
                let mut state = #serde::Serializer::serialize_struct(
                    serializer,
                    #enum_name,
                    1,
                )?;
                #serde::ser::SerializeStruct::serialize_field(
                    &mut state,
                    #tag,
                    #variant_name,
                )?;
                #serde::ser::SerializeStruct::end(state)
            }
        }),
    }
}

/// Generates one adjacently tagged variant arm.
fn adjacent_variant_arm(
    type_name: &syn::Ident,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    tag: &str,
    content: &str,
) -> syn::Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let enum_name = container_attributes.name();
    let arm = match variant.fields() {
        FieldsData::Named(fields) => {
            let (pattern, setups, _conditions, names, carriers) =
                enum_named_parts(
                    type_name,
                    rust_name,
                    fields,
                    runtime,
                    container_attributes,
                    variant,
                );
            let (proxy_definition, proxy_value) =
                named_content_proxy(rust_name, serde, &names, &carriers);
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    #proxy_definition
                    let content_value = #proxy_value;
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #enum_name,
                        2,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #tag,
                        #variant_name,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #content,
                        &content_value,
                    )?;
                    #serde::ser::SerializeStruct::end(state)
                }
            }
        }
        FieldsData::Unnamed(fields) if fields.len() == 1 => {
            let (pattern, setups, _conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, fields, runtime);
            if carriers.is_empty() {
                quote! {
                    Self::#rust_name #pattern => {
                        let mut state = #serde::Serializer::serialize_struct(
                            serializer,
                            #enum_name,
                            1,
                        )?;
                        #serde::ser::SerializeStruct::serialize_field(
                            &mut state,
                            #tag,
                            #variant_name,
                        )?;
                        #serde::ser::SerializeStruct::end(state)
                    }
                }
            } else {
                let carrier = &carriers[0];
                quote! {
                    Self::#rust_name #pattern => {
                        #(#setups)*
                        let has_content = #carrier.is_some();
                        let mut state = #serde::Serializer::serialize_struct(
                            serializer,
                            #enum_name,
                            if has_content { 2 } else { 1 },
                        )?;
                        #serde::ser::SerializeStruct::serialize_field(
                            &mut state,
                            #tag,
                            #variant_name,
                        )?;
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::ser::SerializeStruct::serialize_field(
                                &mut state,
                                #content,
                                carrier,
                            )?;
                        }
                        #serde::ser::SerializeStruct::end(state)
                    }
                }
            }
        }
        FieldsData::Unnamed(fields) => {
            let (pattern, setups, _conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, fields, runtime);
            let (proxy_definition, proxy_value) =
                tuple_content_proxy(rust_name, serde, &carriers);
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    #proxy_definition
                    let content_value = #proxy_value;
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #enum_name,
                        2,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #tag,
                        #variant_name,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #content,
                        &content_value,
                    )?;
                    #serde::ser::SerializeStruct::end(state)
                }
            }
        }
        FieldsData::Unit => quote! {
            Self::#rust_name => {
                let mut state = #serde::Serializer::serialize_struct(
                    serializer,
                    #enum_name,
                    1,
                )?;
                #serde::ser::SerializeStruct::serialize_field(
                    &mut state,
                    #tag,
                    #variant_name,
                )?;
                #serde::ser::SerializeStruct::end(state)
            }
        },
    };
    Ok(arm)
}

/// Generates one untagged variant arm.
fn untagged_variant_arm(
    type_name: &syn::Ident,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> syn::Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let arm = match variant.fields() {
        FieldsData::Named(fields) => {
            let (pattern, setups, conditions, names, carriers) =
                enum_named_parts(
                    type_name,
                    rust_name,
                    fields,
                    runtime,
                    container_attributes,
                    variant,
                );
            let count_conditions = &conditions;
            let calls = conditions.iter().zip(&names).zip(&carriers).map(
                |((_condition, field_name), carrier)| {
                    quote! {
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::ser::SerializeStruct::serialize_field(
                                &mut state,
                                #field_name,
                                carrier,
                            )?;
                        }
                    }
                },
            );
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    let mut field_count = 0usize;
                    #(
                        if #count_conditions {
                            field_count += 1;
                        }
                    )*
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #variant_name,
                        field_count,
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeStruct::end(state)
                }
            }
        }
        FieldsData::Unnamed(fields) if fields.len() == 1 => {
            let (pattern, setups, _conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, fields, runtime);
            if carriers.is_empty() {
                quote! {
                    Self::#rust_name #pattern => {
                        #serde::Serializer::serialize_unit(serializer)
                    }
                }
            } else {
                let carrier = &carriers[0];
                quote! {
                    Self::#rust_name #pattern => {
                        #(#setups)*
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::Serialize::serialize(carrier, serializer)
                        } else {
                            #serde::Serializer::serialize_unit(serializer)
                        }
                    }
                }
            }
        }
        FieldsData::Unnamed(fields) => {
            let (pattern, setups, conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, fields, runtime);
            let count_conditions = &conditions;
            let calls = conditions
                .iter()
                .zip(&carriers)
                .map(|(_condition, carrier)| {
                    quote! {
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::ser::SerializeTuple::serialize_element(
                                &mut state,
                                carrier,
                            )?;
                        }
                    }
                });
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    let mut field_count = 0usize;
                    #(
                        if #count_conditions {
                            field_count += 1;
                        }
                    )*
                    let mut state = #serde::Serializer::serialize_tuple(
                        serializer,
                        field_count,
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeTuple::end(state)
                }
            }
        }
        FieldsData::Unit => quote! {
            Self::#rust_name => #serde::Serializer::serialize_unit(serializer)
        },
    };
    Ok(arm)
}

/// Builds bindings, carriers, names, and conditions for named enum fields.
fn enum_named_parts(
    type_name: &syn::Ident,
    variant_name: &syn::Ident,
    fields: &[NamedField<'_>],
    runtime: &Path,
    container_attributes: &SerdeContainerAttributes,
    variant: &VariantData<'_>,
) -> (
    TokenStream,
    Vec<TokenStream>,
    Vec<TokenStream>,
    Vec<String>,
    Vec<syn::Ident>,
) {
    let patterns = fields.iter().map(|parsed| {
        let identifier = parsed.identifier();
        if field_is_skipped(
            parsed.attributes().mode(),
            parsed.serde_attributes(),
        ) {
            quote!(#identifier: _)
        } else {
            quote!(#identifier)
        }
    });
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut names = Vec::new();
    let mut carriers = Vec::new();
    for (position, parsed) in fields.iter().enumerate() {
        if field_is_skipped(
            parsed.attributes().mode(),
            parsed.serde_attributes(),
        ) {
            continue;
        }
        let field = parsed.field();
        let identifier = parsed.identifier();
        let raw_name = raw_identifier(identifier);
        let container_name =
            container_attributes.rename_variant_field(&raw_name);
        let default_name = variant
            .serde_attributes()
            .rename_field(&raw_name, container_name);
        let serialized_name = parsed
            .serde_attributes()
            .rename()
            .map_or(default_name, str::to_owned);
        let raw = quote_spanned!(field.span()=> #identifier);
        let context = field_context(Some(variant_name), &raw_name);
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let value = serialized_carrier(
            type_name,
            field,
            &context,
            parsed.attributes().mode(),
            runtime,
            raw.clone(),
        );
        let condition = serialization_condition(parsed.serde_attributes(), raw);
        setups.push(quote_spanned! {field.span()=>
            let #carrier = if #condition {
                ::core::option::Option::Some(#value)
            } else {
                ::core::option::Option::None
            };
        });
        conditions.push(quote!(#carrier.is_some()));
        names.push(serialized_name);
        carriers.push(carrier);
    }
    (
        quote!({ #(#patterns),* }),
        setups,
        conditions,
        names,
        carriers,
    )
}

/// Builds bindings, carriers, and conditions for tuple enum fields.
fn enum_unnamed_parts(
    type_name: &syn::Ident,
    variant_name: &syn::Ident,
    fields: &[UnnamedField<'_>],
    runtime: &Path,
) -> (
    TokenStream,
    Vec<TokenStream>,
    Vec<TokenStream>,
    Vec<syn::Ident>,
) {
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
        if field_is_skipped(
            parsed.attributes().mode(),
            parsed.serde_attributes(),
        ) {
            quote!(_)
        } else {
            quote!(#binding)
        }
    });
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut carriers = Vec::new();
    for (position, (parsed, binding)) in
        fields.iter().zip(&bindings).enumerate()
    {
        if field_is_skipped(
            parsed.attributes().mode(),
            parsed.serde_attributes(),
        ) {
            continue;
        }
        let field = parsed.field();
        let field_name = parsed.index().index.to_string();
        let context = field_context(Some(variant_name), &field_name);
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let raw = quote_spanned!(field.span()=> #binding);
        let value = serialized_carrier(
            type_name,
            field,
            &context,
            parsed.attributes().mode(),
            runtime,
            raw.clone(),
        );
        let condition = serialization_condition(parsed.serde_attributes(), raw);
        setups.push(quote_spanned! {field.span()=>
            let #carrier = if #condition {
                ::core::option::Option::Some(#value)
            } else {
                ::core::option::Option::None
            };
        });
        conditions.push(quote!(#carrier.is_some()));
        carriers.push(carrier);
    }
    (quote!((#(#patterns),*)), setups, conditions, carriers)
}

/// Returns one variant's final serialized name.
fn serialized_variant_name(
    variant: &VariantData<'_>,
    container_attributes: &SerdeContainerAttributes,
) -> String {
    let default_name = container_attributes
        .rename_variant(&variant.variant().ident.to_string());
    variant.serde_attributes().rename_variant(default_name)
}

/// Generates a local serializable proxy for adjacent named content.
fn named_content_proxy(
    variant_name: &syn::Ident,
    serde: &Path,
    names: &[String],
    carriers: &[syn::Ident],
) -> (TokenStream, TokenStream) {
    let proxy = format_ident!("__QubitRedactAdjacent{variant_name}Content");
    if carriers.is_empty() {
        let definition = quote! {
            struct #proxy;
            impl #serde::Serialize for #proxy {
                fn serialize<__Serializer>(
                    &self,
                    serializer: __Serializer,
                ) -> ::core::result::Result<
                    __Serializer::Ok,
                    __Serializer::Error,
                >
                where
                    __Serializer: #serde::Serializer,
                {
                    let state = #serde::Serializer::serialize_struct(
                        serializer,
                        stringify!(#variant_name),
                        0,
                    )?;
                    #serde::ser::SerializeStruct::end(state)
                }
            }
        };
        return (definition, quote!(#proxy));
    }
    let value_types = (0..carriers.len())
        .map(|index| format_ident!("__Value{index}"))
        .collect::<Vec<_>>();
    let value_fields = (0..carriers.len())
        .map(|index| format_ident!("value_{index}"))
        .collect::<Vec<_>>();
    let count_fields = &value_fields;
    let calls = names.iter().zip(&value_fields).map(|(name, value)| {
        quote! {
            if let ::core::option::Option::Some(value) = self.#value.as_ref() {
                #serde::ser::SerializeStruct::serialize_field(
                    &mut state,
                    #name,
                    value,
                )?;
            }
        }
    });
    let definition = quote! {
        struct #proxy<#(#value_types),*> {
            #(#value_fields: ::core::option::Option<#value_types>,)*
        }
        impl<#(#value_types),*> #serde::Serialize for #proxy<#(#value_types),*>
        where
            #(#value_types: #serde::Serialize,)*
        {
            fn serialize<__Serializer>(
                &self,
                serializer: __Serializer,
            ) -> ::core::result::Result<
                __Serializer::Ok,
                __Serializer::Error,
            >
            where
                __Serializer: #serde::Serializer,
            {
                let mut field_count = 0usize;
                #(
                    if self.#count_fields.is_some() {
                        field_count += 1;
                    }
                )*
                let mut state = #serde::Serializer::serialize_struct(
                    serializer,
                    stringify!(#variant_name),
                    field_count,
                )?;
                #(#calls)*
                #serde::ser::SerializeStruct::end(state)
            }
        }
    };
    let value = quote! {
        #proxy {
            #(#value_fields: #carriers,)*
        }
    };
    (definition, value)
}

/// Generates a local serializable proxy for adjacent tuple content.
fn tuple_content_proxy(
    variant_name: &syn::Ident,
    serde: &Path,
    carriers: &[syn::Ident],
) -> (TokenStream, TokenStream) {
    let proxy = format_ident!("__QubitRedactAdjacent{variant_name}Content");
    if carriers.is_empty() {
        let definition = quote! {
            struct #proxy;
            impl #serde::Serialize for #proxy {
                fn serialize<__Serializer>(
                    &self,
                    serializer: __Serializer,
                ) -> ::core::result::Result<
                    __Serializer::Ok,
                    __Serializer::Error,
                >
                where
                    __Serializer: #serde::Serializer,
                {
                    let state = #serde::Serializer::serialize_tuple(serializer, 0)?;
                    #serde::ser::SerializeTuple::end(state)
                }
            }
        };
        return (definition, quote!(#proxy));
    }
    let value_types = (0..carriers.len())
        .map(|index| format_ident!("__Value{index}"))
        .collect::<Vec<_>>();
    let value_fields = (0..carriers.len())
        .map(|index| format_ident!("value_{index}"))
        .collect::<Vec<_>>();
    let count_fields = &value_fields;
    let calls = value_fields.iter().map(|value| {
        quote! {
            if let ::core::option::Option::Some(value) = self.#value.as_ref() {
                #serde::ser::SerializeTuple::serialize_element(
                    &mut state,
                    value,
                )?;
            }
        }
    });
    let definition = quote! {
        struct #proxy<#(#value_types),*> {
            #(#value_fields: ::core::option::Option<#value_types>,)*
        }
        impl<#(#value_types),*> #serde::Serialize for #proxy<#(#value_types),*>
        where
            #(#value_types: #serde::Serialize,)*
        {
            fn serialize<__Serializer>(
                &self,
                serializer: __Serializer,
            ) -> ::core::result::Result<
                __Serializer::Ok,
                __Serializer::Error,
            >
            where
                __Serializer: #serde::Serializer,
            {
                let mut field_count = 0usize;
                #(
                    if self.#count_fields.is_some() {
                        field_count += 1;
                    }
                )*
                let mut state = #serde::Serializer::serialize_tuple(
                    serializer,
                    field_count,
                )?;
                #(#calls)*
                #serde::ser::SerializeTuple::end(state)
            }
        }
    };
    let value = quote! {
        #proxy {
            #(#value_fields: #carriers,)*
        }
    };
    (definition, value)
}
