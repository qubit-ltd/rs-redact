// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! The canonical field-name candidate selected by policy classification.

/// Identifies the candidate that matched a configured field rule.
///
/// # Examples
///
/// ```
/// use qubit_redact::{FieldMatchKind, RedactionPolicy};
///
/// let policy = RedactionPolicy::builder()
///     .fields(|fields| {
///         fields.matching(qubit_redact::FieldNameMatching::ExactOrTokenSuffix);
///         fields.secret_sensitive("password");
///     })
///     .expect("the field rules should be valid")
///     .build()
///     .expect("the policy should be valid");
/// let classification = policy.classify_field("db_password");
/// assert_eq!(classification.match_kind(), Some(FieldMatchKind::TokenSuffix));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldMatchKind {
    /// The complete canonical input field name matched.
    Exact,
    /// A semantic token suffix of the input field name matched.
    TokenSuffix,
}
