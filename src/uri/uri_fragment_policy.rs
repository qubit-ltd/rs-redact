// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fragment handling choices for URI redaction.

/// Controls whether URI fragments are retained or masked.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UriFragmentPolicy {
    /// Masks a non-empty fragment using the opaque high-sensitivity mask.
    #[default]
    Redact,
    /// Preserves the raw fragment spelling.
    Preserve,
}
