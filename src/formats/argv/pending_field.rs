// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
// qubit-style: allow source-test-pair
//! Pending option metadata used by heuristic argv redaction.

/// Option metadata waiting for its separate value.
pub(super) struct PendingField {
    /// Canonical option field name.
    pub(super) field: String,
    /// Whether the option uses exact rather than suffix matching.
    pub(super) exact: bool,
}
