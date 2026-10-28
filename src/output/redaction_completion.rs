// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Completion state shared by redaction operations.

/// Describes whether a redaction operation produced all required safe output.
///
/// Completion records whether the safe representation is complete; it does
/// not certify that the source format was valid. A complete safe replacement
/// may carry a parsing reason such as `InvalidUri`.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionCompletion;
/// use qubit_redact::Redactor;
///
/// let output = Redactor::standard().redact_field("password", "raw-secret");
/// assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
/// ```
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionCompletion {
    /// The operation produced a complete safe representation within budget.
    ///
    /// An ordinary sensitivity mask or a complete safe parse-error
    /// replacement is a complete result, not truncation. Inspect reasons or
    /// use a format inspection API when source validity matters.
    Complete,
    /// Input or output was omitted, but non-empty safe substitute text was
    /// emitted.
    Truncated,
    /// The shared output budget could not retain a complete safe replacement.
    Exhausted,
}
