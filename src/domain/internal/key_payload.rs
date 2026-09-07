// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Admission of transformed map keys without recharging source bytes.

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as _;

/// Already transformed key whose source bytes were admitted before masking.
///
/// # Type Parameters
///
/// - `'a`: Borrow of the transformed key retained through serialization.
pub(super) struct KeyPayload<'a>(
    /// Transformed key borrowed until its downstream scalar event finishes.
    pub(super) &'a str,
);

impl Serialize for KeyPayload<'_> {
    /// Charges the transformed key once before forwarding it to the serializer.
    ///
    /// # Errors
    ///
    /// Returns a serializer error for structural or payload exhaustion, or
    /// propagates the downstream serializer error.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the result and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the already transformed scalar.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !super::redact_serialize_scope::admit_node() {
            return Err(S::Error::custom("redaction map key structural budget exceeded"));
        }
        let _node = super::serde_node_guard::SerdeNodeGuard;
        super::redact_serialize_scope::serialize_payload(serializer, self.0)
    }
}
