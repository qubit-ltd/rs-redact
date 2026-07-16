// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy for rendering HTTP text bodies that lack structured fields.

/// Controls whether opaque HTTP text is redacted or rendered unchanged.
///
/// [`TextBodyPolicy::Redact`] is the default because declared `text/*` bodies
/// and text multipart parts do not expose field names that a
/// [`crate::FieldSanitizer`] can match. [`TextBodyPolicy::PassThrough`] is an
/// explicit diagnostic opt-in: callers accept responsibility for ensuring the
/// text does not contain application secrets or unsafe log content. Neither
/// variant scans arbitrary text or detects secrets stored in non-sensitive
/// structured fields.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TextBodyPolicy {
    /// Replaces opaque text with a redaction marker.
    #[default]
    Redact,
    /// Returns opaque text unchanged for diagnostics.
    PassThrough,
}
