// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Supported serde container rename rules.

use syn::LitStr;

/// Case conversion applied to serialized field names.
pub(crate) enum SerdeRenameRule {
    /// Retains field spelling under Serde's lowercase field semantics.
    Lowercase,
    /// Converts letters to uppercase.
    Uppercase,
    /// Converts snake case to Pascal case.
    PascalCase,
    /// Converts snake case to camel case.
    CamelCase,
    /// Retains snake case.
    SnakeCase,
    /// Converts snake case to screaming snake case.
    ScreamingSnakeCase,
    /// Converts snake case to kebab case.
    KebabCase,
    /// Converts snake case to screaming kebab case.
    ScreamingKebabCase,
}

impl SerdeRenameRule {
    /// Parses one standard serde field rename rule.
    ///
    /// # Parameters
    ///
    /// * `literal` - Case-sensitive serde rename rule.
    ///
    /// # Returns
    ///
    /// The corresponding rename rule.
    ///
    /// # Errors
    ///
    /// Returns an error at `literal` for an unsupported rule.
    pub(crate) fn parse(literal: &LitStr) -> syn::Result<Self> {
        match literal.value().as_str() {
            "lowercase" => Ok(Self::Lowercase),
            "UPPERCASE" => Ok(Self::Uppercase),
            "PascalCase" => Ok(Self::PascalCase),
            "camelCase" => Ok(Self::CamelCase),
            "snake_case" => Ok(Self::SnakeCase),
            "SCREAMING_SNAKE_CASE" => Ok(Self::ScreamingSnakeCase),
            "kebab-case" => Ok(Self::KebabCase),
            "SCREAMING-KEBAB-CASE" => Ok(Self::ScreamingKebabCase),
            value => Err(syn::Error::new_spanned(
                literal,
                format!(
                    "unsupported serde rename_all rule `{value}`; use a standard serde field \
                     rename rule",
                ),
            )),
        }
    }

    /// Applies this rule to a Rust field identifier.
    ///
    /// # Parameters
    ///
    /// * `name` - Field name without a raw-identifier prefix.
    ///
    /// # Returns
    ///
    /// The serialized field name.
    pub(crate) fn apply_to_field(&self, name: &str) -> String {
        match self {
            Self::Lowercase | Self::SnakeCase => name.to_owned(),
            Self::Uppercase => name.to_ascii_uppercase(),
            Self::PascalCase => pascal_case(name),
            Self::CamelCase => {
                let mut pascal = pascal_case(name);
                if let Some(first) = pascal.get_mut(..1) {
                    first.make_ascii_lowercase();
                }
                pascal
            }
            Self::ScreamingSnakeCase => name.to_ascii_uppercase(),
            Self::KebabCase => name.replace('_', "-"),
            Self::ScreamingKebabCase => name.to_ascii_uppercase().replace('_', "-"),
        }
    }

    /// Applies this rule to a Rust enum variant identifier.
    ///
    /// # Parameters
    ///
    /// * `name` - Pascal-case Rust variant name.
    ///
    /// # Returns
    ///
    /// The serialized variant name.
    pub(crate) fn apply_to_variant(&self, name: &str) -> String {
        match self {
            Self::Lowercase => name.to_ascii_lowercase(),
            Self::Uppercase => name.to_ascii_uppercase(),
            Self::PascalCase => name.to_owned(),
            Self::CamelCase => {
                let mut output = name.to_owned();
                if let Some(first) = output.get_mut(..1) {
                    first.make_ascii_lowercase();
                }
                output
            }
            Self::SnakeCase => snake_case(name),
            Self::ScreamingSnakeCase => snake_case(name).to_ascii_uppercase(),
            Self::KebabCase => snake_case(name).replace('_', "-"),
            Self::ScreamingKebabCase => snake_case(name).to_ascii_uppercase().replace('_', "-"),
        }
    }
}

/// Converts a snake-case identifier to Pascal case.
///
/// # Parameters
///
/// * `name` - Snake-case identifier to transform.
///
/// # Returns
///
/// A Pascal-case identifier with underscores removed.
fn pascal_case(name: &str) -> String {
    let mut output = String::new();
    let mut capitalize = true;
    for character in name.chars() {
        if character == '_' {
            capitalize = true;
        } else if capitalize {
            output.push(character.to_ascii_uppercase());
            capitalize = false;
        } else {
            output.push(character);
        }
    }
    output
}

/// Converts a Pascal-case variant identifier to snake case.
///
/// # Parameters
///
/// * `name` - Pascal-case Rust variant name.
///
/// # Returns
///
/// A lowercase name with underscores before non-leading uppercase letters.
fn snake_case(name: &str) -> String {
    let mut output = String::new();
    for (index, character) in name.char_indices() {
        if index > 0 && character.is_uppercase() {
            output.push('_');
        }
        output.push(character.to_ascii_lowercase());
    }
    output
}
