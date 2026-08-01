// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Logical in-place redaction contract for text-valued map-like containers.

use crate::{RedactValueMut, RedactionPolicy};

/// Redacts map values in place after classifying each value by its runtime key.
///
/// This provides logical replacement only; see [`RedactValueMut`] for its
/// memory-erasure boundary.
///
/// # Type Parameters
///
/// * `K` - Runtime map-key type used for field classification.
/// * `V` - Mutable map-value type redacted in place.
pub trait RedactMapValueMut<K: ?Sized, V: ?Sized> {
    /// Replaces sensitive values according to `policy`.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy used to classify every runtime key.
    fn redact_map_in_place(&mut self, policy: &RedactionPolicy);
}

impl<M: ?Sized, K: ?Sized, V: ?Sized> RedactMapValueMut<K, V> for M
where
    for<'a> &'a mut M: IntoIterator<Item = (&'a K, &'a mut V)>,
    K: AsRef<str>,
    V: RedactValueMut,
{
    /// Replaces sensitive entry values according to their runtime keys.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy used to classify every runtime key.
    #[inline]
    fn redact_map_in_place(&mut self, policy: &RedactionPolicy) {
        for (key, value) in self {
            let resolved = policy.resolve_field(key.as_ref());
            if let (Some(level), Some(masking)) = (resolved.sensitivity, resolved.masking) {
                value.redact_value_in_place(level, masking);
            }
        }
    }
}
