// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0 (the "License");
// =============================================================================
//! Shared generation of Serde field and container-count events.

use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;
use syn::Path;

/// Generates one named-field serialization and optional skip notification.
///
/// # Parameters
///
/// - `trait_path`: Serde trait providing the field methods.
/// - `state`: Mutable serializer state expression.
/// - `carrier`: Optional serialized field value expression.
/// - `serialized_name`: Serde-visible field name.
/// - `skip_event`: Optional condition for notifying Serde of a skipped field.
///
/// # Returns
///
/// Tokens which emit the field or skipped-field event.
pub(in crate::serde) fn named_field_event(
    trait_path: &Path,
    state: &TokenStream,
    carrier: &TokenStream,
    serialized_name: &str,
    skip_event: Option<&TokenStream>,
) -> TokenStream {
    let notify = skip_event.map(|allowed| {
        quote! {
            else if #allowed {
                #trait_path::skip_field(#state, #serialized_name)?;
            }
        }
    });
    quote! {
        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
            #trait_path::serialize_field(#state, #serialized_name, carrier)?;
        }
        #notify
    }
}

/// Generates one positional-field serialization event.
///
/// # Parameters
///
/// - `trait_path`: Serde trait providing the positional field method.
/// - `method`: Positional serialization method to call.
/// - `state`: Mutable serializer state expression.
/// - `carrier`: Optional serialized field value expression.
///
/// # Returns
///
/// Tokens which emit the positional field when its carrier is present.
pub(in crate::serde) fn positional_field_event(
    trait_path: &Path,
    method: &Ident,
    state: &TokenStream,
    carrier: &TokenStream,
) -> TokenStream {
    quote! {
        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
            #trait_path::#method(#state, carrier)?;
        }
    }
}

/// Generates the count of fields whose carrier conditions are true.
///
/// # Parameters
///
/// - `conditions`: Inclusion conditions for fields in the container.
/// - `initial`: Number of fields already included.
///
/// # Returns
///
/// Tokens which compute the final field count.
pub(in crate::serde) fn field_count(conditions: &[TokenStream], initial: usize) -> TokenStream {
    quote! {
        let mut field_count = #initial;
        #(if #conditions { field_count += 1; })*
    }
}
