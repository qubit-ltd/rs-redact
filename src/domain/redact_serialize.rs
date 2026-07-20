// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Hidden serialization hook for redacted domain objects.

use crate::RedactionPolicy;

/// Serializes a domain object through an explicit redaction policy.
#[doc(hidden)]
pub trait RedactSerialize {
    /// Serializes the redacted representation of this object.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy snapshot governing serialization.
    /// * `serializer` - Destination serde serializer.
    ///
    /// # Returns
    ///
    /// The serializer's success value.
    ///
    /// # Errors
    ///
    /// Returns the destination serializer's error unchanged.
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}
