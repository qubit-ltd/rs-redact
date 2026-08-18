// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Completion state shared by redaction operations.

/// Describes whether a redaction operation produced all required safe output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionCompletion {
    /// All input was processed and its complete safe output fit the budget.
    ///
    /// An ordinary sensitivity mask is a complete result, not truncation.
    Complete,
    /// Input or output was omitted, but non-empty safe substitute text was
    /// emitted.
    Truncated,
}
