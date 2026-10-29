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

/// Checks whether a path's generic type arguments use `Self`.
pub(super) fn path_has_self_type_argument(path: &Path) -> bool {
    path.segments.iter().any(|segment| {
        let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
            return false;
        };
        arguments.args.iter().any(|argument| match argument {
            GenericArgument::Type(ty) => type_uses_self(ty),
            GenericArgument::AssocType(associated) => type_uses_self(&associated.ty),
            _ => false,
        })
    })
}

fn type_uses_self(ty: &Type) -> bool {
    match ty {
        Type::Reference(value) => type_uses_self(&value.elem),
        Type::Tuple(value) => value.elems.iter().any(type_uses_self),
        Type::Array(value) => type_uses_self(&value.elem),
        Type::Slice(value) => type_uses_self(&value.elem),
        Type::Ptr(value) => type_uses_self(&value.elem),
        Type::Paren(value) => type_uses_self(&value.elem),
        Type::Group(value) => type_uses_self(&value.elem),
        Type::Path(type_path) => {
            type_path.qself.as_ref().is_some_and(|qself| type_uses_self(&qself.ty))
                || type_path
                    .path
                    .segments
                    .first()
                    .is_some_and(|segment| segment.ident == "Self")
                || path_has_self_type_argument(&type_path.path)
        }
        Type::FnPtr(value) => {
            value.inputs.iter().any(|argument| type_uses_self(&argument.ty))
                || match &value.output {
                    syn::ReturnType::Default => false,
                    syn::ReturnType::Type(_, ty) => type_uses_self(ty.as_ref()),
                }
        }
        _ => false,
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
    match ty {
        Type::Reference(value) => replace_self_in_type(&mut value.elem, source, generics),
        Type::Tuple(value) => {
            for element in &mut value.elems {
                replace_self_in_type(element, source, generics);
            }
        }
        Type::Array(value) => replace_self_in_type(&mut value.elem, source, generics),
        Type::Slice(value) => replace_self_in_type(&mut value.elem, source, generics),
        Type::Ptr(value) => replace_self_in_type(&mut value.elem, source, generics),
        Type::Paren(value) => replace_self_in_type(&mut value.elem, source, generics),
        Type::Group(value) => replace_self_in_type(&mut value.elem, source, generics),
        Type::FnPtr(value) => {
            for argument in &mut value.inputs {
                replace_self_in_type(&mut argument.ty, source, generics);
            }
            if let syn::ReturnType::Type(_, ty) = &mut value.output {
                replace_self_in_type(ty.as_mut(), source, generics);
            }
        }
        _ => {}
    }
    let Type::Path(type_path) = ty else {
        return;
    };
    if let Some(qself) = &mut type_path.qself {
        replace_self_in_type(&mut qself.ty, source, generics);
    }
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
            type_path.path.leading_colon = Some(Default::default());
            type_path.path.segments = remaining;
        }
        return;
    }
    replace_self_in_path_arguments(&mut type_path.path, source, generics);
}

#[cfg(test)]
mod tests {
    use quote::ToTokens;
    use syn::Generics;
    use syn::Ident;
    use syn::Type;
    use syn::parse_quote;

    use super::replace_self_in_type;
    use super::type_uses_self;

    #[test]
    fn test_bare_function_self_detection_and_replacement() {
        let source: Ident = parse_quote!(Source);
        let generics: Generics = parse_quote!(<'a, T, const N: usize>);

        let cases: [(Type, Type); 3] = [
            (parse_quote!(fn(Self)), parse_quote!(fn(Source<'a, T, N>))),
            (parse_quote!(fn() -> Self), parse_quote!(fn() -> Source<'a, T, N>)),
            (
                parse_quote!(Option<fn(Self)>),
                parse_quote!(Option<fn(Source<'a, T, N>)>),
            ),
        ];
        for (mut ty, expected) in cases {
            assert!(type_uses_self(&ty));
            replace_self_in_type(&mut ty, &source, &generics);
            assert_eq!(ty.to_token_stream().to_string(), expected.to_token_stream().to_string());
        }
    }

    #[test]
    fn test_bare_function_preserves_non_self_parts() {
        let source: Ident = parse_quote!(Source);
        let generics: Generics = parse_quote!(<'a, T, const N: usize>);
        let mut ty: Type = parse_quote!(for<'b> unsafe extern "C" fn(&'b Self) -> Self);
        assert!(type_uses_self(&ty));
        replace_self_in_type(&mut ty, &source, &generics);
        let expected: Type = parse_quote!(for<'b> unsafe extern "C" fn(&'b Source<'a, T, N>) -> Source<'a, T, N>);
        assert_eq!(ty.to_token_stream().to_string(), expected.to_token_stream().to_string());

        let mut no_self: Type = parse_quote!(unsafe extern "C" fn(u8) -> u16);
        let original = no_self.to_token_stream().to_string();
        assert!(!type_uses_self(&no_self));
        replace_self_in_type(&mut no_self, &source, &generics);
        assert_eq!(no_self.to_token_stream().to_string(), original);
    }
}
