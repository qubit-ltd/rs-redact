// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy for rendering HTTP text bodies that lack structured fields.

/// Controls whether opaque HTTP text is redacted or rendered unchanged.
///
/// [`Self::Redact`] is the safe default. [`Self::PassThrough`] is an explicit
/// diagnostic opt-in and may expose application secrets.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TextBodyPolicy {
    /// Replaces opaque text with a redaction marker.
    #[default]
    Redact,
    /// Preserves opaque text for diagnostics.
    PassThrough,
}
