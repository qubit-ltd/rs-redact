// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Derivation of transparent scalar capabilities without business trait
//! takeover.

use proc_macro2::TokenStream;
use quote::quote;
use syn::Data;
use syn::DeriveInput;
use syn::Error;
use syn::Member;
use syn::Path;
use syn::Result;
use syn::parse_quote;

/// Generates scalar delegation for exactly one scalar field.
///
/// Returns a targeted error for non-struct shapes, multiple fields, or field
/// redaction attributes: scalar types do not declare a sensitivity themselves.
pub(crate) fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let runtime = crate::runtime_path::resolve(input)?;
    let Data::Struct(data) = &input.data else {
        return Err(Error::new_spanned(
            input,
            "RedactScalar requires a single-field struct",
        ));
    };
    if data.fields.len() != 1 {
        return Err(Error::new_spanned(
            input,
            "RedactScalar requires exactly one scalar field",
        ));
    }
    let field = data
        .fields
        .iter()
        .next()
        .expect("validated one-field scalar");
    for attribute in &field.attrs {
        if attribute.path().is_ident("redact") {
            return Err(Error::new_spanned(
                attribute,
                "RedactScalar does not declare field sensitivity; annotate the consuming field",
            ));
        }
    }
    for attribute in &input.attrs {
        if attribute.path().is_ident("redact") {
            attribute.parse_nested_meta(|meta| {
                if !meta.path.is_ident("crate") {
                    return Err(meta.error("RedactScalar only accepts `crate = path`"));
                }
                let _: Path = meta.value()?.parse()?;
                Ok(())
            })?;
        }
    }
    let member = field
        .ident
        .clone()
        .map_or_else(|| Member::Unnamed(0.into()), Member::Named);
    let ty = &field.ty;
    let name = &input.ident;
    let serializer =
        crate::expand::assertions::fresh_identifier(&input.generics, "__QuibitScalarSerializer");
    let mut generics = input.generics.clone();
    generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(#ty: #runtime::RedactScalar));
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    let mut serde_generics = generics.clone();
    serde_generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(#ty: #runtime::domain::internal::RedactLevelSerialize));
    let (serde_impl, _, serde_where) = serde_generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics #runtime::domain::LevelValueSealed for #name #type_generics #where_clause {}
        impl #impl_generics #runtime::RedactScalar for #name #type_generics #where_clause {}
        impl #impl_generics #runtime::domain::RedactLevelValue for #name #type_generics #where_clause {
            fn write_redacted_level(&self, writer: &mut #runtime::RedactionWriter<'_>, level: #runtime::Sensitivity) {
                #runtime::domain::RedactLevelValue::write_redacted_level(&self.#member, writer, level);
            }
        }
        #runtime::__qubit_redact_scalar_serde! {
            impl #serde_impl #runtime::domain::internal::RedactLevelSerialize for #name #type_generics #serde_where {
                fn serialize_redacted_level<#serializer>(&self, serializer: #serializer, policy: &#runtime::RedactionPolicy, level: #runtime::Sensitivity)
                    -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where #serializer: #runtime::domain::internal::serde::Serializer {
                    #runtime::domain::internal::RedactLevelSerialize::serialize_redacted_level(&self.#member, serializer, policy, level)
                }
            }
        }
    })
}
