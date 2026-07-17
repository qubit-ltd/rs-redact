// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy for JSON scalar values without an object-field context.

/// Controls whether unkeyed JSON scalar values are redacted or preserved.
///
/// [`Self::Redact`] is the default because top-level scalar values and scalar
/// elements in unkeyed arrays have no field name that a
/// [`crate::FieldSanitizer`] can classify. [`Self::PassThrough`] is an explicit
/// diagnostic opt-in and may expose application secrets.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UnkeyedJsonValuePolicy {
    /// Replaces unkeyed scalar values with a fixed redaction marker.
    #[default]
    Redact,
    /// Preserves unkeyed scalar values unchanged for diagnostics.
    PassThrough,
}
