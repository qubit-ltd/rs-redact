// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Generated structured serialization capability.

use serde::Serializer;

use crate::RedactionPolicy;

/// Legacy structured-redaction hook for manually implemented container
/// adapters. Derived domain values use the projection capability instead.
pub trait RedactSerialize {
    /// Serializes this value through a caller-supplied policy.
    fn serialize_redacted<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}
