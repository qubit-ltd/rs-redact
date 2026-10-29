// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Lazy carriers used to reproject an explicitly self-recursive field.
//!
//! Recursive detection is syntactic and preserves the complete generic target
//! identity. Lazy carriers support direct targets, `Option<Box<T>>`, and
//! `Vec<Box<T>>`; this module does not resolve arbitrary wrapper aliases.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use syn::DeriveInput;
use syn::GenericArgument;
use syn::GenericParam;
use syn::PathArguments;
use syn::Type;
use syn::parse_quote;

use super::internal::rebind_source_generics;
use crate::expand::assertions;
use crate::model::ContainerData;
use crate::model::FieldMode;
use crate::model::FieldsData;

/// Identifies the supported outer storage shape for a self-recursive field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecursiveShape {
    /// The field directly stores the derived type.
    Direct,
    /// The field stores an optional boxed derived type.
    OptionBox,
    /// The field stores boxed derived values in a vector.
    VecBox,
}

/// Returns the supported self-recursive shape of a field type.
///
/// Recognition is based on the complete target type, including its generic
/// arguments, and accepts only direct targets, `Option<Box<T>>`, or
/// `Vec<Box<T>>` with the syntactically supported wrapper paths.
pub(super) fn shape(input: &DeriveInput, ty: &Type) -> Option<RecursiveShape> {
    let target = assertions::recursive_target(input);
    shape_for_target(&target, ty)
}

/// Matches a field type against a target identity and supported storage shape.
///
/// Direct target types are recognized before wrapper inspection. Wrapped forms
/// must have exactly one type argument at each level and use `Box` inside
/// `Option` or `Vec`; arbitrary aliases and additional generic arguments are
/// not resolved.
pub(super) fn shape_for_target(target: &str, ty: &Type) -> Option<RecursiveShape> {
    if is_target_type(ty, target) {
        return Some(RecursiveShape::Direct);
    }
    let Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() || !supported_wrapper_path(&path.path) {
        return None;
    }
    let outer = path.path.segments.last()?;
    let expected_inner = match outer.ident.to_string().as_str() {
        "Option" => RecursiveShape::OptionBox,
        "Vec" => RecursiveShape::VecBox,
        _ => return None,
    };
    let PathArguments::AngleBracketed(arguments) = &outer.arguments else {
        return None;
    };
    let [GenericArgument::Type(inner)] = arguments.args.iter().collect::<Vec<_>>().as_slice() else {
        return None;
    };
    let Type::Path(box_path) = inner else {
        return None;
    };
    if box_path.qself.is_some() || !supported_wrapper_path(&box_path.path) {
        return None;
    }
    let box_segment = box_path.path.segments.last()?;
    if box_segment.ident != "Box" {
        return None;
    }
    let PathArguments::AngleBracketed(box_arguments) = &box_segment.arguments else {
        return None;
    };
    let [GenericArgument::Type(target_type)] = box_arguments.args.iter().collect::<Vec<_>>().as_slice() else {
        return None;
    };
    is_target_type(target_type, target).then_some(expected_inner)
}

/// Generates the carrier helpers and factory for a recursively derived type.
///
/// No tokens are emitted unless the model has a supported recursive field and
/// has no unskipped unsupported recursive field. The generated carriers borrow
/// their source values and reproject them lazily during serialization.
pub(super) fn expand(
    input: &DeriveInput,
    projection: &syn::Ident,
    model: &ContainerData<'_>,
    marker: &syn::Ident,
    runtime: &syn::Path,
    serde: &syn::Path,
) -> TokenStream {
    if !supports_recursive_projection(input, model) {
        return TokenStream::new();
    }
    let name = &input.ident;
    let name_string = name.to_string();
    let type_fragment = name_string.trim_start_matches("r#");
    let carrier = format_ident!("__QubitRedact{}RecursiveValue", type_fragment);
    let optional = format_ident!("__QubitRedact{}RecursiveOption", type_fragment);
    let vector = format_ident!("__QubitRedact{}RecursiveVec", type_fragment);
    let factory = format_ident!("__qubit_redact_{}_reproject", name.to_string().trim_start_matches("r#"));
    let serde = quote!(#serde);
    let runtime = quote!(#runtime);
    let lifetime = assertions::fresh_lifetime(&input.generics);
    let fields = collect_fields(model);
    let projection_arguments = fields
        .iter()
        .map(|field| concrete_field_type(input, &field.ty))
        .collect::<Vec<_>>();
    let source_arguments = input
        .generics
        .params
        .iter()
        .map(|parameter| match parameter {
            GenericParam::Lifetime(parameter) => {
                let lifetime = &parameter.lifetime;
                quote!(#lifetime)
            }
            GenericParam::Type(parameter) => {
                let ident = &parameter.ident;
                quote!(#ident)
            }
            GenericParam::Const(parameter) => {
                let ident = &parameter.ident;
                quote!(#ident)
            }
        })
        .collect::<Vec<_>>();
    let (_, source_type_generics, _) = input.generics.split_for_impl();
    let projection_type = quote!(#projection<#lifetime, #(#source_arguments,)* #(#projection_arguments),*>);
    let mut factory_generics = rebind_source_generics(name, &input.generics);
    factory_generics
        .params
        .insert(0, GenericParam::Lifetime(parse_quote!(#lifetime)));
    let (factory_impl_generics, _, factory_where_clause) = factory_generics.split_for_impl();
    let constructor = super::entry::projection_constructor_for(name, projection, model, marker, quote!(value));
    quote! {
        #[doc(hidden)]
        struct #carrier<'__value, T, P> {
            value: &'__value T,
            reproject: fn(&'__value T) -> P,
        }

        impl<'__value, T, P> #carrier<'__value, T, P> {
            fn new(value: &'__value T, reproject: fn(&'__value T) -> P) -> Self {
                Self { value, reproject }
            }
        }

        impl<'__value, T, P> #serde::Serialize for #carrier<'__value, T, P>
        where P: #serde::Serialize {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where S: #serde::Serializer {
                #serde::Serialize::serialize(&(self.reproject)(self.value), serializer)
            }
        }

        #[doc(hidden)]
        struct #optional<'__value, T, P> {
            value: &'__value ::core::option::Option<::std::boxed::Box<T>>,
            reproject: fn(&'__value T) -> P,
        }

        impl<'__value, T, P> #serde::Serialize for #optional<'__value, T, P>
        where P: #serde::Serialize {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where S: #serde::Serializer {
                match self.value.as_ref() {
                    ::core::option::Option::Some(value) => #serde::Serializer::serialize_some(serializer, &#carrier::new(value.as_ref(), self.reproject)),
                    ::core::option::Option::None => #serde::Serializer::serialize_none(serializer),
                }
            }
        }

        #[doc(hidden)]
        struct #vector<'__value, T, P> {
            value: &'__value ::std::vec::Vec<::std::boxed::Box<T>>,
            reproject: fn(&'__value T) -> P,
        }

        impl<'__value, T, P> #serde::Serialize for #vector<'__value, T, P>
        where P: #serde::Serialize {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where S: #serde::Serializer {
                use #serde::ser::SerializeSeq;
                let policy_owner = #runtime::domain::internal::current_policy()
                    .ok_or_else(|| {
                        <S::Error as #serde::ser::Error>::custom(
                            "serialization requires an active redaction scope",
                        )
                    })?;
                #runtime::domain::internal::serialize_structured(
                    serializer,
                    policy_owner.as_ref(),
                    |serializer| {
                        #runtime::domain::internal::admit_serializer_items(
                            &serializer, self.value.len(),
                        )?;
                        let mut sequence = serializer.serialize_seq(Some(self.value.len()))?;
                        for value in self.value {
                            sequence.serialize_element(
                                &#carrier::new(value.as_ref(), self.reproject),
                            )?;
                        }
                        sequence.end()
                    },
                )
            }
        }

        fn #factory #factory_impl_generics (value: &#lifetime #name #source_type_generics) -> #projection_type #factory_where_clause {
            #constructor
        }
    }
}

/// Generates the recursive carrier expression for a borrowed source field.
///
/// The shape selects a direct value carrier, an optional boxed-value carrier,
/// or a vector-of-boxed-values carrier; each uses the generated reprojection
/// factory.
pub(super) fn carrier_expression(type_name: &syn::Ident, shape: RecursiveShape, value: TokenStream) -> TokenStream {
    let type_name_string = type_name.to_string();
    let type_fragment = type_name_string.trim_start_matches("r#");
    let carrier = format_ident!("__QubitRedact{}RecursiveValue", type_fragment);
    let optional = format_ident!("__QubitRedact{}RecursiveOption", type_fragment);
    let vector = format_ident!("__QubitRedact{}RecursiveVec", type_fragment);
    let factory = format_ident!(
        "__qubit_redact_{}_reproject",
        type_name.to_string().trim_start_matches("r#")
    );
    match shape {
        RecursiveShape::Direct => quote!(#carrier::new(#value, #factory)),
        RecursiveShape::OptionBox => quote!(#optional { value: #value, reproject: #factory }),
        RecursiveShape::VecBox => quote!(#vector { value: #value, reproject: #factory }),
    }
}

/// Replaces occurrences of `Self` in a field type with the concrete derived
/// type.
///
/// Replacement follows type paths' angle-bracketed type arguments, tuples,
/// arrays, parenthesized types, references, and raw pointers. Other type syntax
/// is left unchanged.
pub(super) fn concrete_field_type(input: &DeriveInput, field_type: &Type) -> TokenStream {
    let name = &input.ident;
    let (_, type_generics, _) = input.generics.split_for_impl();
    let source_type: Type = parse_quote!(#name #type_generics);
    let mut field_type = field_type.clone();
    replace_self_type(&mut field_type, &source_type);
    quote!(#field_type)
}

/// Reports whether an unskipped nested field has a supported recursive shape.
///
/// Serde-skipped fields and Serde-skipped enum variants are excluded from this
/// check; other field filtering is not performed here.
pub(super) fn has_recursive_field(input: &DeriveInput, model: &ContainerData<'_>) -> bool {
    let recursive = |fields: &FieldsData<'_>| match fields {
        FieldsData::Named(fields) => fields.iter().any(|field| {
            !field.serde_attributes().skip()
                && matches!(field.attributes().mode(), FieldMode::Nested)
                && shape(input, &field.field().ty).is_some()
        }),
        FieldsData::Unnamed(fields) => fields.iter().any(|field| {
            !field.serde_attributes().skip()
                && matches!(field.attributes().mode(), FieldMode::Nested)
                && shape(input, &field.field().ty).is_some()
        }),
        FieldsData::Unit => false,
    };
    match model {
        ContainerData::Struct(fields) => recursive(fields),
        ContainerData::Enum(variants) => variants
            .iter()
            .filter(|variant| !variant.serde_attributes().skip())
            .any(|variant| recursive(variant.fields())),
    }
}

/// Reports whether an unskipped field contains recursion the carriers cannot
/// handle.
///
/// A recursive field is supported here only when it is in nested mode and has
/// one of the recognized shapes. Serde-skipped fields and variants are ignored.
pub(super) fn has_unsupported_recursive_field(input: &DeriveInput, model: &ContainerData<'_>) -> bool {
    let recursive = |fields: &FieldsData<'_>| match fields {
        FieldsData::Named(fields) => fields.iter().any(|field| {
            !field.serde_attributes().skip()
                && assertions::contains_recursive_type(input, &field.field().ty)
                && !(matches!(field.attributes().mode(), FieldMode::Nested)
                    && shape(input, &field.field().ty).is_some())
        }),
        FieldsData::Unnamed(fields) => fields.iter().any(|field| {
            !field.serde_attributes().skip()
                && assertions::contains_recursive_type(input, &field.field().ty)
                && !(matches!(field.attributes().mode(), FieldMode::Nested)
                    && shape(input, &field.field().ty).is_some())
        }),
        FieldsData::Unit => false,
    };
    match model {
        ContainerData::Struct(fields) => recursive(fields),
        ContainerData::Enum(variants) => variants
            .iter()
            .filter(|variant| !variant.serde_attributes().skip())
            .any(|variant| recursive(variant.fields())),
    }
}

/// Determines whether recursive carrier generation is safe for the whole model.
///
/// Returns true only when at least one supported recursive field exists and no
/// unskipped unsupported recursive field exists.
pub(super) fn supports_recursive_projection(input: &DeriveInput, model: &ContainerData<'_>) -> bool {
    has_recursive_field(input, model) && !has_unsupported_recursive_field(input, model)
}

/// Checks whether a type is `Self` or matches the complete recursive target
/// identity.
///
/// `Self` is accepted directly; other types are compared using the recursive
/// type matcher, including the target's generic arguments.
fn is_target_type(ty: &Type, target: &str) -> bool {
    if matches!(ty, Type::Path(path) if path.qself.is_none() && path.path.is_ident("Self")) {
        return true;
    }
    assertions::matches_recursive_type(ty, target)
}

/// Accepts an unqualified wrapper path or one rooted at `std`, `alloc`, or
/// `core`.
///
/// This is a syntactic path check; it does not resolve imports or aliases.
fn supported_wrapper_path(path: &syn::Path) -> bool {
    path.segments.len() == 1
        || path
            .segments
            .first()
            .is_some_and(|segment| matches!(segment.ident.to_string().as_str(), "std" | "alloc" | "core"))
}

/// Replaces `Self` recursively in the type forms handled by this module.
///
/// It visits type arguments in paths, tuples, arrays, parentheses, references,
/// and pointers. Other syntax is left unchanged.
fn replace_self_type(ty: &mut Type, source: &Type) {
    match ty {
        Type::Path(path) if path.qself.is_none() && path.path.is_ident("Self") => {
            *ty = source.clone();
        }
        Type::Path(path) => {
            for segment in &mut path.path.segments {
                if let PathArguments::AngleBracketed(arguments) = &mut segment.arguments {
                    for argument in &mut arguments.args {
                        if let GenericArgument::Type(ty) = argument {
                            replace_self_type(ty, source);
                        }
                    }
                }
            }
        }
        Type::Tuple(tuple) => {
            for element in &mut tuple.elems {
                replace_self_type(element, source);
            }
        }
        Type::Array(array) => replace_self_type(&mut array.elem, source),
        Type::Paren(paren) => replace_self_type(&mut paren.elem, source),
        Type::Reference(reference) => replace_self_type(&mut reference.elem, source),
        Type::Ptr(pointer) => replace_self_type(&mut pointer.elem, source),
        _ => {}
    }
}

/// Collects every declared field in the model, preserving declaration order.
///
/// This helper does not filter Serde-skipped fields or variants.
fn collect_fields<'a>(model: &ContainerData<'a>) -> Vec<&'a syn::Field> {
    let mut fields = Vec::new();
    match model {
        ContainerData::Struct(group) => collect_group_fields(group, &mut fields),
        ContainerData::Enum(variants) => {
            for variant in variants {
                collect_group_fields(variant.fields(), &mut fields);
            }
        }
    }
    fields
}

/// Collects every declared field in a field group without applying skip
/// filters.
fn collect_group_fields<'a>(group: &FieldsData<'a>, fields: &mut Vec<&'a syn::Field>) {
    match group {
        FieldsData::Named(items) => fields.extend(items.iter().map(|field| field.field())),
        FieldsData::Unnamed(items) => fields.extend(items.iter().map(|field| field.field())),
        FieldsData::Unit => {}
    }
}

#[cfg(test)]
mod tests {
    use syn::DeriveInput;
    use syn::Type;
    use syn::parse_quote;

    use super::RecursiveShape;
    use super::shape;
    use super::shape_for_target;
    use crate::expand::assertions;

    #[test]
    fn test_recursive_shape_requires_complete_generic_identity() {
        let input: DeriveInput = parse_quote! {
            struct Node<T, U> {
                value: T,
                next: Option<Box<Node<T, U>>>,
            }
        };
        let exact: Type = parse_quote!(Option<Box<Node<T, U>>>);
        let alternating: Type = parse_quote!(Option<Box<Node<U, T>>>);
        let target = assertions::recursive_target(&input);

        assert_eq!(shape(&input, &exact), Some(RecursiveShape::OptionBox));
        assert_eq!(shape(&input, &alternating), None);
        assert_eq!(shape_for_target(&target, &exact), Some(RecursiveShape::OptionBox));
        assert_eq!(shape_for_target(&target, &alternating), None);
    }
}
