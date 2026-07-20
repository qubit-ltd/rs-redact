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
    /// Converts letters to lowercase.
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
    pub(crate) fn apply(&self, name: &str) -> String {
        match self {
            Self::Lowercase => name.to_ascii_lowercase(),
            Self::Uppercase => name.to_ascii_uppercase(),
            Self::PascalCase => pascal_case(name),
            Self::CamelCase => {
                let pascal = pascal_case(name);
                let mut characters = pascal.chars();
                match characters.next() {
                    Some(first) => {
                        first.to_lowercase().chain(characters).collect()
                    }
                    None => String::new(),
                }
            }
            Self::SnakeCase => name.to_owned(),
            Self::ScreamingSnakeCase => name.to_ascii_uppercase(),
            Self::KebabCase => name.replace('_', "-"),
            Self::ScreamingKebabCase => {
                name.to_ascii_uppercase().replace('_', "-")
            }
        }
    }
}

/// Converts a snake-case identifier to Pascal case.
fn pascal_case(name: &str) -> String {
    let mut output = String::new();
    for word in name.split('_').filter(|word| !word.is_empty()) {
        let mut characters = word.chars();
        if let Some(first) = characters.next() {
            output.extend(first.to_uppercase());
            output.extend(characters);
        }
    }
    output
}
