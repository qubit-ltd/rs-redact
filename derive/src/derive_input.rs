// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Named-struct validation and code generation for `Redact`.

use proc_macro2::TokenStream;
use quote::{
    quote,
    quote_spanned,
};
use syn::{
    Data,
    DeriveInput,
    Fields,
    Path,
    spanned::Spanned,
};

use crate::{
    container_attributes::ContainerAttributes,
    field_attributes::FieldAttributes,
    field_mode::FieldMode,
    serde_attributes::SerdeAttributes,
};

/// Expands a named-field struct into its runtime `Redact` implementation.
///
/// # Parameters
///
/// * `input` - Parsed derive input whose generics and fields are preserved.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
///
/// # Returns
///
/// Generated implementation tokens for a named-field struct.
///
/// # Errors
///
/// Returns a targeted syntax error when `input` is not a named-field struct or
/// a named field unexpectedly has no identifier.
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
) -> syn::Result<TokenStream> {
    let container_attributes = ContainerAttributes::parse(input)?;
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => fields,
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    "Redact can only be derived for structs with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "Redact can only be derived for structs with named fields",
            ));
        }
    };

    let parsed_fields = fields
        .named
        .iter()
        .map(|field| {
            let identifier = field.ident.as_ref().ok_or_else(|| {
                syn::Error::new_spanned(
                    field,
                    "Redact requires every field to have a name",
                )
            })?;
            let attributes =
                FieldAttributes::parse(field, &input.ident, identifier)?;
            let serde_attributes = SerdeAttributes::parse(
                field,
                &input.ident,
                identifier,
                container_attributes.serde_enabled(),
            )?;
            Ok((field, identifier, attributes, serde_attributes))
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let field_calls = parsed_fields
        .iter()
        .map(|(field, identifier, attributes, _serde_attributes)| {
            let field_name = identifier.to_string();
            match attributes.mode() {
                FieldMode::Plain => quote_spanned! {field.span()=>
                    .field(#field_name, &self.#identifier)
                },
                FieldMode::Level(sensitivity) => {
                    let level = sensitivity.runtime_tokens(runtime);
                    quote_spanned! {field.span()=>
                        .field(
                            #field_name,
                            &#runtime::RedactValue::redact_value(
                                &self.#identifier,
                                #level,
                                policy.masking(),
                            ),
                        )
                    }
                }
                FieldMode::Skip => TokenStream::new(),
                FieldMode::Nested => quote_spanned! {field.span()=>
                    .field(
                        #field_name,
                        &#runtime::Redact::redacted_with(&self.#identifier, policy),
                    )
                },
                FieldMode::Map => quote_spanned! {field.span()=>
                    .field(
                        #field_name,
                        &#runtime::RedactedMap::new(&self.#identifier, policy.clone()),
                    )
                },
            }
        })
        .collect::<Vec<_>>();
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) =
        input.generics.split_for_impl();
    let serde_impl = if container_attributes.serde_enabled() {
        let serialized_fields = parsed_fields
            .iter()
            .filter_map(|(field, identifier, attributes, serde_attributes)| {
                if matches!(attributes.mode(), FieldMode::Skip) || serde_attributes.skip() {
                    return None;
                }
                let raw_name = identifier.to_string();
                let raw_name = raw_name.strip_prefix("r#").unwrap_or(&raw_name);
                let serialized_name = serde_attributes
                    .rename()
                    .map_or_else(|| container_attributes.rename_field(raw_name), str::to_owned);
                let condition = serde_attributes.skip_serializing_if().map_or_else(
                    || quote!(true),
                    |predicate| quote_spanned!(field.span()=> !(#predicate)(&self.#identifier)),
                );
                let value = match attributes.mode() {
                    FieldMode::Plain => quote_spanned!(field.span()=> &self.#identifier),
                    FieldMode::Level(sensitivity) => {
                        let level = sensitivity.runtime_tokens(runtime);
                        quote_spanned! {field.span()=>
                            &#runtime::RedactValue::redact_value(
                                &self.#identifier,
                                #level,
                                policy.masking(),
                            )
                        }
                    }
                    FieldMode::Nested => quote_spanned! {field.span()=>
                        &#runtime::__private::RedactedSerialize::new(
                            &self.#identifier,
                            policy,
                        )
                    },
                    FieldMode::Map => quote_spanned! {field.span()=>
                        &#runtime::RedactedMap::new(
                            &self.#identifier,
                            policy.clone(),
                        )
                    },
                    FieldMode::Skip => return None,
                };
                Some((condition, serialized_name, value))
            })
            .collect::<Vec<_>>();
        let count_conditions =
            serialized_fields.iter().map(|(condition, _, _)| condition);
        let serialize_calls = serialized_fields.iter().map(
            |(condition, serialized_name, value)| {
                quote! {
                    if #condition {
                        #runtime::__private::serde::ser::SerializeStruct::serialize_field(
                            &mut state,
                            #serialized_name,
                            #value,
                        )?;
                    }
                }
            },
        );
        quote! {
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
                        __QubitRedactSerializer:
                            #runtime::__private::serde::Serializer,
                    {
                        let mut field_count = 0usize;
                        #(
                            if #count_conditions {
                                field_count += 1;
                            }
                        )*
                        let mut state =
                            #runtime::__private::serde::Serializer::serialize_struct(
                                serializer,
                                stringify!(#name),
                                field_count,
                            )?;
                        #(#serialize_calls)*
                        #runtime::__private::serde::ser::SerializeStruct::end(state)
                    }
                }
            }
        }
    } else {
        TokenStream::new()
    };

    Ok(quote! {
        impl #impl_generics #runtime::Redact for #name #type_generics #where_clause {
            fn fmt_redacted(
                &self,
                policy: &#runtime::RedactionPolicy,
                formatter: &mut ::core::fmt::Formatter<'_>,
            ) -> ::core::fmt::Result {
                let _ = policy;
                formatter
                    .debug_struct(stringify!(#name))
                    #(#field_calls)*
                    .finish()
            }
        }
        #serde_impl
    })
}

/// Expands a named-field struct into its runtime `RedactMut` implementation.
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
/// Returns a targeted syntax error when `input` is not a named-field struct,
/// a field has no identifier, or a redaction attribute is invalid.
pub(crate) fn expand_mut(
    input: &DeriveInput,
    runtime: &Path,
) -> syn::Result<TokenStream> {
    let _container_attributes = ContainerAttributes::parse(input)?;
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => fields,
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    "RedactMut can only be derived for structs with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "RedactMut can only be derived for structs with named fields",
            ));
        }
    };

    let mutations = fields
        .named
        .iter()
        .map(|field| {
            let identifier = field.ident.as_ref().ok_or_else(|| {
                syn::Error::new_spanned(
                    field,
                    "RedactMut requires every field to have a name",
                )
            })?;
            let attributes =
                FieldAttributes::parse(field, &input.ident, identifier)?;
            let mutation = match attributes.mode() {
                FieldMode::Plain | FieldMode::Skip => TokenStream::new(),
                FieldMode::Level(sensitivity) => {
                    let level = sensitivity.runtime_tokens(runtime);
                    quote_spanned! {field.span()=>
                        #runtime::RedactValueMut::redact_value_in_place(
                            &mut self.#identifier,
                            #level,
                            policy.masking(),
                        );
                    }
                }
                FieldMode::Nested => quote_spanned! {field.span()=>
                    #runtime::RedactMut::redact_in_place_with(
                        &mut self.#identifier,
                        policy,
                    );
                },
                FieldMode::Map => quote_spanned! {field.span()=>
                    #runtime::RedactMapValueMut::redact_map_in_place(
                        &mut self.#identifier,
                        policy,
                    );
                },
            };
            Ok(mutation)
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) =
        input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #runtime::RedactMut for #name #type_generics #where_clause {
            fn redact_in_place_with(&mut self, policy: &#runtime::RedactionPolicy) {
                let _ = policy;
                #(#mutations)*
            }
        }
    })
}
