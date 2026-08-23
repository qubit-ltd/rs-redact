// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Failure classes produced while admitting JSON text.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JsonAdmissionError {
    /// The input is not one complete JSON value.
    Invalid,
    /// A structural or JSON-specific limit rejected the input.
    Limit,
}
