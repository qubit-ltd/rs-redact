// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Observable result of borrowed JSON serialization.

/// Reports whether an admitted JSON serialization passed through unkeyed
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonRedactionOutcome {
    /// Traversal completed, optionally passing through an unkeyed scalar.
    Complete {
        /// Whether at least one unkeyed scalar remained visible.
        passed_unkeyed: bool,
    },
}
