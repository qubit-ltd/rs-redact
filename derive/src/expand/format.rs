// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Optional safe formatting implementations generated with `Redact`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::Data;
use syn::DeriveInput;
use syn::Fields;
use syn::Generics;
use syn::Path;

use crate::attributes::ContainerAttributes;
/// Generates the requested `Debug` and `Display` implementations.
///
/// # Parameters
///
/// * `input` - Complete derive input whose generics are preserved.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
/// * `attributes` - Parsed container formatting controls.
/// * `generics` - Input generics plus bounds required by the redaction impl.
///
/// # Returns
///
/// Empty tokens when neither implementation was requested, otherwise the
/// requested implementations delegating to the structured redaction writer.
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
    attributes: &ContainerAttributes,
    generics: &Generics,
) -> TokenStream {
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let debug_body = if attributes.transparent() {
        match &input.data {
            Data::Struct(data) => match &data.fields {
                Fields::Named(fields) => {
                    let field = fields
                        .named
                        .first()
                        .and_then(|field| field.ident.as_ref())
                        .expect("validated transparent field");
                    quote! {
                        formatter.write_str(concat!(stringify!(#name), " { ", stringify!(#field), ": "))?;
                        formatter.write_str(output.text().as_str())?;
                        formatter.write_str(" }")
                    }
                }
                Fields::Unnamed(_) => quote! {
                    formatter.write_str(concat!(stringify!(#name), "("))?;
                    formatter.write_str(output.text().as_str())?;
                    formatter.write_str(")")
                },
                Fields::Unit => {
                    unreachable!("transparent unit structs are rejected")
                }
            },
            Data::Enum(_) | Data::Union(_) => {
                unreachable!("transparent requires a struct")
            }
        }
    } else {
        quote!(formatter.write_str(output.text().as_str()))
    };
    let debug_impl = attributes.debug_enabled().then(|| {
        quote! {
            impl #impl_generics ::core::fmt::Debug for #name #type_generics #where_clause {
                #[inline(always)]
                fn fmt(
                    &self,
                    formatter: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    let output = #runtime::Redactor::application_default().redact(self);
                    #debug_body
                }
            }
        }
    });
    let display_impl = attributes.display_enabled().then(|| {
        quote! {
            impl #impl_generics ::core::fmt::Display for #name #type_generics #where_clause {
                #[inline(always)]
                fn fmt(
                    &self,
                    formatter: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    let output = #runtime::Redactor::application_default().redact(self);
                    formatter.write_str(output.text().as_str())
                }
            }
        }
    });

    quote! {
        #debug_impl
        #display_impl
    }
}
