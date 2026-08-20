// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! The canonical field-name candidate selected by policy classification.

/// Identifies the candidate that matched a configured field rule.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldMatchKind {
    /// The complete canonical input field name matched.
    Exact,
    /// A semantic token suffix of the input field name matched.
    TokenSuffix,
}
