// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy for JSON scalar values without an object-field context.

/// Controls whether unkeyed JSON scalar values are redacted or preserved.
///
/// Unkeyed scalars are root scalar values and scalar elements of arrays.
/// Object property values remain keyed even when their field rule passes
/// through.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UnkeyedJsonValuePolicy {
    /// Replaces unkeyed scalar values with the Secret opaque mask.
    #[default]
    Redact,
    /// Preserves unkeyed scalar values for diagnostics.
    PassThrough,
}
