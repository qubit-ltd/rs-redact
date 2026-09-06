// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Result of bounded scalar-field rendering.

use crate::RedactionCompletion;
use crate::RedactionReasons;

/// Result of formatting one scalar while enforcing both input and output caps.
pub(super) struct FieldRender {
    pub(super) text: String,
    pub(super) completion: RedactionCompletion,
    pub(super) reasons: RedactionReasons,
    pub(super) presented_value_bytes: usize,
    pub(super) inspected_value_bytes: usize,
}
