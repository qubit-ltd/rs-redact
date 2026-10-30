// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Rebinds source `Self` references before source constraints move into
//! helpers.

use syn::ExprPath;
use syn::Generics;
use syn::Ident;
use syn::Path;
use syn::Type;
use syn::TypePath;
use syn::parse_quote;
use syn::visit_mut::VisitMut;

/// Rewrites `Self` roots in a cloned set of source generic constraints.
struct SourceSelfRebinder {
    /// Concrete source type used for each rebound `Self` root.
    source_type: Type,
}

impl SourceSelfRebinder {
    /// Rewrites an unqualified source `Self` type path while preserving qself
    /// paths.
    fn replace_type_path(&self, path: &mut TypePath) {
        if path.qself.is_some() || !starts_with_self(&path.path) {
            return;
        }
        let Some(replacement) = rebound_type_path(&self.source_type, &path.path) else {
            return;
        };
        *path = replacement;
    }

    /// Rewrites an expression path rooted at source `Self` when it has an
    /// opaque supported suffix.
    fn replace_expr_path(&self, path: &mut ExprPath) {
        if path.qself.is_some() || !starts_with_self(&path.path) {
            return;
        }
        let source_type = &self.source_type;
        let suffix = path_suffix(&path.path);
        if suffix.segments.is_empty() {
            let Type::Path(source_type) = &self.source_type else {
                return;
            };
            path.path = source_type.path.clone();
            return;
        }
        *path = parse_quote!(<#source_type>::#suffix);
    }
}

impl VisitMut for SourceSelfRebinder {
    fn visit_type_path_mut(&mut self, path: &mut TypePath) {
        syn::visit_mut::visit_type_path_mut(self, path);
        self.replace_type_path(path);
    }

    fn visit_expr_path_mut(&mut self, path: &mut ExprPath) {
        syn::visit_mut::visit_expr_path_mut(self, path);
        self.replace_expr_path(path);
    }
}

/// Rebinds source `Self` references in a cloned set of generic constraints.
pub(in crate::serde) fn rebind_source_generics(source: &Ident, generics: &Generics) -> Generics {
    let (_, arguments, _) = generics.split_for_impl();
    let source_type = parse_quote!(#source #arguments);
    let mut rebound = generics.clone();
    SourceSelfRebinder { source_type }.visit_generics_mut(&mut rebound);
    rebound
}

/// Rebinds source `Self` references in a cloned field type to the complete
/// source type.
///
/// The source lifetime, type, and const arguments are preserved. Existing qself
/// roots are traversed for nested types, while opaque token forms remain
/// unchanged.
///
/// # Parameters
///
/// * `source` - Identifier of the derived source type.
/// * `generics` - Generic parameters declared by the source type.
/// * `ty` - Field type written in the source type's lexical context.
///
/// # Returns
///
/// A cloned type with supported source `Self` roots rebound to the source type.
pub(in crate::serde) fn rebind_source_type(source: &Ident, generics: &Generics, ty: &Type) -> Type {
    let (_, arguments, _) = generics.split_for_impl();
    let source_type = parse_quote!(#source #arguments);
    let mut rebound = ty.clone();
    SourceSelfRebinder { source_type }.visit_type_mut(&mut rebound);
    rebound
}

/// Returns whether the first path segment denotes lexical `Self`.
fn starts_with_self(path: &Path) -> bool {
    path.segments.first().is_some_and(|segment| segment.ident == "Self")
}

/// Copies all path segments after the lexical `Self` root.
fn path_suffix(path: &Path) -> Path {
    Path {
        leading_colon: None,
        segments: path.segments.iter().skip(1).cloned().collect(),
    }
}

/// Combines a concrete source type with a supported associated-item suffix.
fn rebound_type_path(source_type: &Type, path: &Path) -> Option<TypePath> {
    let suffix = path_suffix(path);
    if suffix.segments.is_empty() {
        return Some(parse_quote!(#source_type));
    }
    Some(parse_quote!(<#source_type>::#suffix))
}

#[cfg(test)]
mod tests {
    use proc_macro2::TokenStream;
    use quote::ToTokens;
    use quote::quote;
    use syn::DeriveInput;
    use syn::Generics;
    use syn::Ident;
    use syn::Type;
    use syn::parse_quote;

    use super::rebind_source_generics;
    use super::rebind_source_type;

    fn parse_generics(tokens: TokenStream) -> Generics {
        let input: DeriveInput = syn::parse2(quote!(struct Test #tokens;)).expect("valid source generics");
        input.generics
    }

    fn assert_rebound(actual: Generics, expected: Generics) {
        assert_eq!(
            actual.into_token_stream().to_string(),
            expected.into_token_stream().to_string()
        );
    }

    #[test]
    fn test_rebinds_source_self_in_type_constraints() {
        let source: Ident = parse_quote!(Source);
        assert_rebound(
            rebind_source_generics(
                &source,
                &parse_generics(quote!(<'a, T, const N: usize> where Self: Marker)),
            ),
            parse_generics(quote!(<'a, T, const N: usize> where Source<'a, T, N>: Marker)),
        );
        assert_rebound(
            rebind_source_generics(
                &source,
                &parse_generics(quote!(<'a, T, const N: usize> where T: Uses<Self>)),
            ),
            parse_generics(quote!(<'a, T, const N: usize> where T: Uses<Source<'a, T, N>>)),
        );
        assert_rebound(
            rebind_source_generics(
                &source,
                &parse_generics(quote!(<'a, T, const N: usize> where <Self as HasAssoc>::Assoc: Clone)),
            ),
            parse_generics(quote!(<'a, T, const N: usize> where <Source<'a, T, N> as HasAssoc>::Assoc: Clone)),
        );
        assert_rebound(
            rebind_source_generics(
                &source,
                &parse_generics(quote!(<'a, T, const N: usize> where Self::Assoc: Clone)),
            ),
            parse_generics(quote!(<'a, T, const N: usize> where <Source<'a, T, N>>::Assoc: Clone)),
        );
        assert_rebound(
            rebind_source_generics(
                &source,
                &parse_generics(quote!(<'a, T, const N: usize> where for<'b> &'b Self: Trait)),
            ),
            parse_generics(quote!(<'a, T, const N: usize> where for<'b> &'b Source<'a, T, N>: Trait)),
        );
    }

    #[test]
    fn test_rebinds_source_self_in_const_expressions() {
        let source: Ident = parse_quote!(Source);
        assert_rebound(
            rebind_source_generics(
                &source,
                &parse_generics(quote!(<'a, T, const N: usize> where [u8; Self::SIZE]: Copy)),
            ),
            parse_generics(quote!(<'a, T, const N: usize> where [u8; <Source<'a, T, N>>::SIZE]: Copy)),
        );
    }

    #[test]
    fn test_preserves_generics_without_source_self() {
        let source: Ident = parse_quote!(Source);
        let original = parse_generics(quote!(<'a, T: Clone, const N: usize> where T: Send));
        assert_rebound(rebind_source_generics(&source, &original), original);
    }

    #[test]
    fn test_rebinds_source_self_in_field_type_shapes() {
        let source: Ident = parse_quote!(Source);
        let generics = parse_generics(quote!(<'a, T, const N: usize>));
        let cases: [(Type, Type); 4] = [
            (
                parse_quote!(std::marker::PhantomData<Self>),
                parse_quote!(std::marker::PhantomData<Source<'a, T, N>>),
            ),
            (
                parse_quote!(<Self as HasAssoc>::Assoc),
                parse_quote!(<Source<'a, T, N> as HasAssoc>::Assoc),
            ),
            (
                parse_quote!(fn(&'a Self) -> Self),
                parse_quote!(fn(&'a Source<'a, T, N>) -> Source<'a, T, N>),
            ),
            (
                parse_quote!(Option<<Self as HasAssoc>::Assoc>),
                parse_quote!(Option<<Source<'a, T, N> as HasAssoc>::Assoc>),
            ),
        ];
        for (ty, expected) in cases {
            assert_eq!(
                rebind_source_type(&source, &generics, &ty)
                    .into_token_stream()
                    .to_string(),
                expected.into_token_stream().to_string()
            );
        }
    }
}
