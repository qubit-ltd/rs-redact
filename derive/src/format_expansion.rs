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
use syn::{DeriveInput, Path};

use crate::container_attributes::ContainerAttributes;

/// Generates the requested `Debug` and `Display` implementations.
///
/// # Parameters
///
/// * `input` - Complete derive input whose generics are preserved.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
/// * `attributes` - Parsed container formatting controls.
///
/// # Returns
///
/// Empty tokens when neither implementation was requested, otherwise the
/// requested implementations delegating to the existing redacted view.
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
    attributes: &ContainerAttributes,
) -> TokenStream {
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    let debug_impl = attributes.debug_enabled().then(|| {
        quote! {
            impl #impl_generics ::core::fmt::Debug for #name #type_generics #where_clause {
                #[inline(always)]
                fn fmt(
                    &self,
                    formatter: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    let redacted = <Self as #runtime::Redact>::redacted(self);
                    ::core::fmt::Debug::fmt(&redacted, formatter)
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
                    let redacted = <Self as #runtime::Redact>::redacted(self);
                    ::core::fmt::Display::fmt(&redacted, formatter)
                }
            }
        }
    });

    quote! {
        #debug_impl
        #display_impl
    }
}
