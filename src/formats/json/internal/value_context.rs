// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serialization context for one borrowed JSON value.

use crate::Sensitivity;

/// Determines how a JSON value is emitted by the redacting serializer.
#[derive(Clone, Copy)]
pub(super) enum ValueContext {
    /// The value has no governing object-field rule.
    Unkeyed,
    /// The enclosing object key resolved to this sensitivity.
    Keyed(Sensitivity),
    /// The enclosing object key permits the original value to pass through.
    PassThrough,
}
