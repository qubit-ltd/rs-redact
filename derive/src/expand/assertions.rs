// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Generic capability bounds inferred from selected field modes.

use std::collections::BTreeSet;

use proc_macro2::Span;
use proc_macro2::TokenStream;
use proc_macro2::TokenTree;
use quote::ToTokens;
use quote::format_ident;
use quote::quote;
use syn::Field;
use syn::GenericParam;
use syn::Generics;
use syn::Ident;
use syn::Lifetime;
use syn::Path;
use syn::Type;
use syn::WhereClause;
use syn::WherePredicate;
use syn::parse_quote;
use syn::punctuated::Punctuated;
use syn::token::Comma;

use crate::model::ContainerData;
use crate::model::FieldMode;
use crate::model::FieldsData;
/// Adds capability bounds needed by borrowing redaction.
///
/// Bounds are added only when a field type refers to one of the input's type
/// parameters. Concrete fields retain the compact impl that existed before
/// bound inference was introduced. Map and JSON modes use the runtime
/// capability traits, preserving their field-type-specific diagnostics.
///
/// # Parameters
///
/// * `generics` - Input generics plus bounds required by the redaction impl.
/// * `model` - Parsed fields and their selected redaction modes.
/// * `runtime` - Resolved path to the runtime crate.
pub(crate) fn add_redact_bounds(generics: &mut Generics, model: &ContainerData<'_>, runtime: &Path) {
    for_each_field(model, &mut |field, mode, _serialize_with| match mode {
        FieldMode::Unmarked => {
            add_trait_bound(generics, field, quote!(::core::fmt::Debug));
        }
        FieldMode::KeyedBy(_) => {
            add_trait_bound(generics, field, quote!(::core::fmt::Debug));
            add_trait_bound(generics, field, quote!(#runtime::domain::RedactLevelValue));
        }
        FieldMode::DisplayLevel(_) => add_trait_bound(generics, field, quote!(::core::fmt::Display)),
        FieldMode::Level(_) => {
            add_trait_bound(generics, field, quote!(#runtime::domain::RedactLevelValue));
        }
        FieldMode::Nested => {
            add_trait_bound(generics, field, quote!(#runtime::Redact));
        }
        FieldMode::Map => add_trait_bound(generics, field, quote!(#runtime::domain::RedactMapValue)),
        FieldMode::MapLevels { .. } => add_trait_bound(generics, field, quote!(#runtime::domain::RedactMapKeyValue)),
        FieldMode::Json => add_trait_bound(generics, field, quote!(#runtime::domain::RedactJsonValue)),
        FieldMode::Skip => {}
    });
}

/// Visits every parsed field without exposing the container representation to
/// each bound-inference caller.
///
/// # Parameters
///
/// * `model` - Parsed struct or enum to visit.
/// * `callback` - Visitor receiving the source field, redaction mode, and
///   optional adapter.
fn for_each_field(model: &ContainerData<'_>, callback: &mut impl FnMut(&Field, &FieldMode, Option<&Path>)) {
    match model {
        ContainerData::Struct(fields) => for_each_fields(fields, callback),
        ContainerData::Enum(variants) => {
            for variant in variants {
                for_each_fields(variant.fields(), callback);
            }
        }
    }
}

/// Visits one parsed field collection.
///
/// # Parameters
///
/// * `fields` - Named, tuple, or unit field collection.
/// * `callback` - Visitor receiving each field and its validated controls.
fn for_each_fields(fields: &FieldsData<'_>, callback: &mut impl FnMut(&Field, &FieldMode, Option<&Path>)) {
    match fields {
        FieldsData::Named(fields) => {
            for field in fields {
                callback(
                    field.field(),
                    field.attributes().mode(),
                    field.serde_attributes().serialize_with(),
                );
            }
        }
        FieldsData::Unnamed(fields) => {
            for field in fields {
                callback(
                    field.field(),
                    field.attributes().mode(),
                    field.serde_attributes().serialize_with(),
                );
            }
        }
        FieldsData::Unit => {}
    }
}

/// Adds one trait predicate when the field type uses an input type parameter.
///
/// # Parameters
///
/// * `generics` - Generic declaration to extend without duplicate predicates.
/// * `field` - Field whose type may need a capability bound.
/// * `trait_path` - Capability trait expressed as generated tokens.
fn add_trait_bound(generics: &mut Generics, field: &Field, trait_path: TokenStream) {
    if !uses_type_parameter(generics, &field.ty) {
        return;
    }
    let field_type = &field.ty;
    let predicate: WherePredicate = parse_quote!(#field_type: #trait_path);
    let candidate = predicate.to_token_stream().to_string();
    let where_clause = generics.make_where_clause();
    if where_clause
        .predicates
        .iter()
        .any(|item| item.to_token_stream().to_string() == candidate)
    {
        return;
    }
    where_clause.predicates.push(predicate);
}

/// Returns whether a field type contains an input type parameter identifier.
///
/// # Parameters
///
/// * `generics` - Input declaration supplying candidate type parameters.
/// * `field_type` - Field type to inspect recursively.
///
/// # Returns
///
/// `true` when any field-type token names an input type parameter.
#[must_use]
fn uses_type_parameter(generics: &Generics, field_type: &impl ToTokens) -> bool {
    let parameters: Vec<String> = generics
        .params
        .iter()
        .filter_map(|parameter| {
            let GenericParam::Type(parameter) = parameter else {
                return None;
            };
            Some(parameter.ident.to_string())
        })
        .collect();
    token_stream_uses_parameter(field_type.to_token_stream(), &parameters)
}

/// Selects the input generic parameters referenced by one field type.
///
/// The returned generics retain only parameters and where predicates needed by
/// the field. Generated local carrier items can therefore introduce their own
/// generic parameters instead of capturing the surrounding impl's parameters.
///
/// # Parameters
///
/// * `generics` - Input generic parameters and where predicates.
/// * `field_type` - Field type whose referenced parameters are retained.
///
/// # Returns
///
/// Filtered generics containing referenced parameters and transitively related
/// inline bounds and where predicates.
#[must_use]
pub(crate) fn generics_for_field(generics: &Generics, field_type: &Type) -> Generics {
    let parameter_names = generic_parameter_names(generics);
    let mut used = BTreeSet::new();
    collect_parameter_names(field_type.to_token_stream(), &parameter_names, &mut used);

    loop {
        let mut changed = false;
        for parameter in &generics.params {
            if used.contains(&generic_parameter_name(parameter)) {
                for name in parameter_names_in(parameter, &parameter_names) {
                    changed |= used.insert(name);
                }
            }
        }
        if let Some(where_clause) = &generics.where_clause {
            for predicate in &where_clause.predicates {
                let names = parameter_names_in(predicate, &parameter_names);
                if names.iter().any(|name| used.contains(name)) {
                    changed |= names.iter().any(|name| used.insert(name.clone()));
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut filtered = generics.clone();
    filtered.params = generics
        .params
        .iter()
        .filter(|parameter| used.contains(&generic_parameter_name(parameter)))
        .cloned()
        .collect();
    filtered.where_clause = filtered.where_clause.and_then(|where_clause| {
        let predicates: Punctuated<WherePredicate, Comma> = where_clause
            .predicates
            .into_iter()
            .filter(|predicate| {
                let names = parameter_names_in(predicate, &parameter_names);
                names.iter().any(|name| used.contains(name))
            })
            .collect();
        if predicates.is_empty() {
            None
        } else {
            Some(WhereClause {
                where_token: where_clause.where_token,
                predicates,
            })
        }
    });
    filtered
}

/// Creates an identifier that cannot collide with an input generic parameter.
///
/// # Parameters
///
/// * `generics` - Input declaration supplying occupied parameter names.
/// * `base` - Valid Rust identifier to use directly or suffix with an integer.
///
/// # Returns
///
/// An available identifier based on `base`.
///
/// # Panics
///
/// Panics if `base` is not a valid identifier or every generated suffix is
/// occupied.
#[must_use]
pub(crate) fn fresh_identifier(generics: &Generics, base: &str) -> Ident {
    let used = generic_parameter_names(generics);
    if !used.contains(base) {
        return format_ident!("{base}");
    }
    (0..)
        .map(|index| format_ident!("{base}_{index}"))
        .find(|candidate| !used.contains(&candidate.to_string()))
        .expect("an unused generated identifier should always exist")
}

/// Creates a lifetime that cannot collide with an input generic lifetime.
///
/// # Parameters
///
/// * `generics` - Input declaration supplying occupied parameter names.
///
/// # Returns
///
/// A fresh lifetime beginning with `__qubit_redact_lifetime`.
///
/// # Panics
///
/// Panics only if every generated numeric suffix is occupied.
#[must_use]
pub(crate) fn fresh_lifetime(generics: &Generics) -> Lifetime {
    let used = generic_parameter_names(generics);
    let base = "__qubit_redact_lifetime";
    let name = if !used.contains(base) {
        base.to_owned()
    } else {
        (0..)
            .map(|index| format!("{base}_{index}"))
            .find(|candidate| !used.contains(candidate))
            .expect("an unused generated lifetime should always exist")
    };
    Lifetime::new(&format!("'{name}"), Span::call_site())
}

/// Returns generic parameter names declared by one input.
///
/// # Parameters
///
/// * `generics` - Declaration whose type, lifetime, and const names are
///   collected.
///
/// # Returns
///
/// The set of declared names without lifetime apostrophes.
#[must_use]
fn generic_parameter_names(generics: &Generics) -> BTreeSet<String> {
    generics.params.iter().map(generic_parameter_name).collect()
}

/// Returns the textual name of one type, lifetime, or const parameter.
///
/// # Parameters
///
/// * `parameter` - Generic parameter to name.
///
/// # Returns
///
/// The parameter identifier without a lifetime apostrophe.
#[must_use]
fn generic_parameter_name(parameter: &GenericParam) -> String {
    match parameter {
        GenericParam::Type(parameter) => parameter.ident.to_string(),
        GenericParam::Const(parameter) => parameter.ident.to_string(),
        GenericParam::Lifetime(parameter) => parameter.lifetime.ident.to_string(),
    }
}

/// Returns generic names used by one token stream.
///
/// # Parameters
///
/// * `tokens` - Syntax tokens to inspect recursively.
/// * `candidates` - Generic parameter names eligible for inclusion.
///
/// # Returns
///
/// Candidate names occurring in the token stream.
#[must_use]
fn parameter_names_in(tokens: &impl ToTokens, candidates: &BTreeSet<String>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_parameter_names(tokens.to_token_stream(), candidates, &mut names);
    names
}

/// Recursively collects candidate generic names from token groups.
///
/// # Parameters
///
/// * `tokens` - Token stream to inspect.
/// * `candidates` - Declared generic names eligible for inclusion.
/// * `names` - Destination set extended with matching identifiers.
fn collect_parameter_names(tokens: TokenStream, candidates: &BTreeSet<String>, names: &mut BTreeSet<String>) {
    for token in tokens {
        match token {
            TokenTree::Ident(identifier) => {
                let name = identifier.to_string();
                if candidates.contains(&name) {
                    names.insert(name);
                }
            }
            TokenTree::Group(group) => {
                collect_parameter_names(group.stream(), candidates, names);
            }
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

/// Searches a field type's token stream for an input type parameter.
///
/// # Parameters
///
/// * `tokens` - Field-type token stream to inspect recursively.
/// * `parameters` - Candidate input type parameter names.
///
/// # Returns
///
/// `true` if any identifier matches a candidate type parameter.
#[must_use]
fn token_stream_uses_parameter(tokens: TokenStream, parameters: &[String]) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(identifier) => {
            let name = identifier.to_string();
            parameters.iter().any(|parameter| parameter == &name)
        }
        TokenTree::Group(group) => token_stream_uses_parameter(group.stream(), parameters),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}
