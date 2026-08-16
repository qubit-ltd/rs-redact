// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Status of a bounded HTTP body redaction result.

use super::BodyRedactionReason;

/// Describes how an HTTP body was represented for diagnostics.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyRedactionStatus {
    /// The available bounded body bytes were empty.
    Empty,
    /// Structured parsing and configured field redaction succeeded.
    Structured,
    /// Policy explicitly allowed at least one value to remain visible.
    PassedThrough,
    /// The complete body representation was replaced fail-closed.
    Redacted(
        /// Reason a structured or visible representation was unsafe.
        BodyRedactionReason,
    ),
    /// Non-UTF-8 binary data was represented only by a size summary.
    Binary,
}
