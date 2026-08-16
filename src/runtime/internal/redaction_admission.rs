// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Admission result for one bounded redaction fragment.

/// Describes whether a redaction fragment may inspect and render its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedactionAdmission {
    /// The complete input was admitted and output may be rendered up to the
    /// supplied byte ceiling.
    Render { max_output_bytes: usize },
    /// Input was rejected and the terminal fail-closed marker was charged.
    Fallback,
    /// No further fragment or fallback may be emitted.
    Exhausted,
}
