// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Status returned after appending a diagnostic fragment.

/// Result of appending one diagnostic fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticWriteStatus {
    /// The complete fragment fit within the output budget.
    Complete,
    /// The output budget was exhausted and the truncation marker was emitted.
    Truncated,
}
