// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serialized variant names and adjacent-content proxy generation.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::Path;

use crate::{internal::VariantData, serde_container_attributes::SerdeContainerAttributes};

/// Returns one variant's final serialized name.
pub(super) fn serialized_variant_name(
    variant: &VariantData<'_>,
    container_attributes: &SerdeContainerAttributes,
) -> String {
    let default_name = container_attributes.rename_variant(&variant.variant().ident.to_string());
    variant.serde_attributes().rename_variant(default_name)
}

/// Generates a local serializable proxy for adjacent named content.
pub(super) fn named_content_proxy(
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
pub(super) fn tuple_content_proxy(
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
