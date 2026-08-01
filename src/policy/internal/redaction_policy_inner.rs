// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Complete immutable state shared by redaction policy clones.

use std::collections::{
    BTreeMap,
    BTreeSet,
};

use crate::policy::{
    FieldNameMatching,
    Sensitivity,
    UnknownFieldPolicy,
};

/// Complete immutable state shared by policy clones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedactionPolicyInner {
    /// Canonical sensitive fields and their levels.
    pub(in crate::policy) sensitive: BTreeMap<String, Sensitivity>,
    /// Canonical fields allowed only as complete names.
    pub(in crate::policy) allow_exact: BTreeSet<String>,
    /// Canonical fields allowed at exact and token-suffix boundaries.
    pub(in crate::policy) allow_suffix: BTreeSet<String>,
    /// Candidate-generation breadth for sensitive-field matching.
    pub(in crate::policy) matching: FieldNameMatching,
    /// Fallback behavior for fields with no matching rule.
    pub(in crate::policy) unknown_field_policy: UnknownFieldPolicy,
}
