// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Field-name matching modes used by redaction policies.

/// Controls which canonical field-name candidates may match policy rules.
///
/// # Examples
///
/// ```
/// use qubit_redact::{FieldNameMatching, RedactionPolicy};
///
/// let policy = RedactionPolicy::builder()
///     .fields(|fields| {
///         fields.matching(FieldNameMatching::ExactOrTokenSuffix);
///     })
///     .expect("the field rules should be valid")
///     .build()
///     .expect("the policy should be valid");
/// assert_eq!(policy.matching(), FieldNameMatching::ExactOrTokenSuffix);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldNameMatching {
    /// Matches only the complete canonical field name.
    Exact,
    /// Matches the complete name and semantic token suffixes.
    ExactOrTokenSuffix,
}
