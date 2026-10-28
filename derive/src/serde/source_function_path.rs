// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Rebinds leading `Self` in Serde function paths to the source type.

use proc_macro2::TokenStream;
use quote::quote;
use syn::AngleBracketedGenericArguments;
use syn::GenericArgument;
use syn::Generics;
use syn::Ident;
use syn::Path;
use syn::PathArguments;
use syn::Type;

/// Source type identity needed while emitting Serde attribute paths.
pub(super) struct SourceTypeContext<'a> {
    pub(super) ident: &'a Ident,
    pub(super) generics: &'a Generics,
}
use syn::parse_quote;

/// Generates a function path in the lexical context of the derived source.
///
/// Leading `Self` is replaced by the complete source type, including its
/// declared generic arguments. Other paths are emitted unchanged.
#[must_use]
pub(super) fn source_function_path(context: &SourceTypeContext<'_>, path: &Path) -> TokenStream {
    let mut path = path.clone();
    replace_self_in_path_arguments(&mut path, context.ident, context.generics);
    let Some(first) = path.segments.first() else {
        return quote!(#path);
    };
    if first.ident != "Self" {
        return quote!(#path);
    }
    let (_, type_generics, _) = context.generics.split_for_impl();
    let rest = path.segments.iter().skip(1);
    if path.segments.len() == 1 {
        let source = context.ident;
        quote!(#source #type_generics)
    } else {
        let source = context.ident;
        quote!(<#source #type_generics>::#(#rest)::* )
    }
}

fn replace_self_in_path_arguments(path: &mut Path, source: &Ident, generics: &Generics) {
    for segment in &mut path.segments {
        if let PathArguments::AngleBracketed(arguments) = &mut segment.arguments {
            replace_self_in_arguments(arguments, source, generics);
        }
    }
}

fn replace_self_in_arguments(arguments: &mut AngleBracketedGenericArguments, source: &Ident, generics: &Generics) {
    for argument in &mut arguments.args {
        match argument {
            GenericArgument::Type(ty) => replace_self_in_type(ty, source, generics),
            GenericArgument::AssocType(associated) => replace_self_in_type(&mut associated.ty, source, generics),
            _ => {}
        }
    }
}

fn replace_self_in_type(ty: &mut Type, source: &Ident, generics: &Generics) {
    let Type::Path(type_path) = ty else {
        return;
    };
    let (_, type_generics, _) = generics.split_for_impl();
    let source_type: Type = parse_quote!(#source #type_generics);
    if let Some(first) = type_path.path.segments.first()
        && first.ident == "Self"
    {
        let remaining = type_path
            .path
            .segments
            .iter()
            .skip(1)
            .cloned()
            .collect::<syn::punctuated::Punctuated<_, syn::Token![::]>>();
        if remaining.is_empty() {
            type_path.qself = None;
            type_path.path = match source_type {
                Type::Path(source_type) => source_type.path,
                _ => unreachable!(),
            };
        } else {
            type_path.qself = Some(syn::QSelf {
                lt_token: Default::default(),
                ty: Box::new(source_type),
                position: 0,
                as_token: None,
                gt_token: Default::default(),
            });
            type_path.path.segments = remaining;
        }
        return;
    }
    replace_self_in_path_arguments(&mut type_path.path, source, generics);
}
