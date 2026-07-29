// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stateless redaction operations backed by an immutable policy.

use std::borrow::Cow;

use crate::{
    RedactMapValueMut,
    RedactedKeyedValue,
    RedactedText,
    RedactionPolicy,
    Sensitivity,
};

/// Applies one immutable policy to scalar values and string maps.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redactor {
    /// Field classification and masking configuration.
    policy: RedactionPolicy,
}

impl Redactor {
    /// Creates a redactor using `policy`.
    ///
    /// # Parameters
    ///
    /// * `policy` - Immutable field classification and masking configuration.
    ///
    /// # Returns
    ///
    /// A redactor that owns the supplied policy snapshot.
    #[inline(always)]
    pub const fn new(policy: RedactionPolicy) -> Self {
        Self { policy }
    }

    /// Returns the immutable policy used by this redactor.
    ///
    /// # Returns
    ///
    /// A borrowed view of the redactor's policy snapshot.
    #[must_use = "use the policy snapshot backing this redactor"]
    #[inline(always)]
    pub const fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Redacts one value according to its field name.
    ///
    /// Unknown and explicitly allowed fields retain a borrow of `value`.
    /// Sensitive fields return the value produced by the configured mask.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of the input and any borrowed redacted result.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    /// * `value` - Field value to redact when classified as sensitive.
    ///
    /// # Returns
    ///
    /// Typed redacted text borrowing safe input where possible.
    #[must_use = "use the returned redacted value"]
    #[inline]
    pub fn redact<'a>(&self, field: &str, value: &'a str) -> RedactedText<'a> {
        let value = match self.policy.sensitivity_for(field) {
            Some(level) => self.policy.masking().mask(level, value),
            None => Cow::Borrowed(value),
        };
        RedactedText::new(value)
    }

    /// Redacts one value at an explicit sensitivity level.
    ///
    /// This ignores field classification and allow rules. Use it at a boundary
    /// where the value is known to be sensitive regardless of its field name.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of the input and any borrowed redacted result.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity required by the calling boundary.
    /// * `value` - Value to mask.
    ///
    /// # Returns
    ///
    /// Typed redacted text produced by the configured mask for `level`.
    #[must_use = "use the returned redacted value"]
    #[inline]
    pub fn redact_at<'a>(
        &self,
        level: Sensitivity,
        value: &'a str,
    ) -> RedactedText<'a> {
        RedactedText::new(self.policy.masking().mask(level, value))
    }

    /// Creates a lazy redacted view selected by an external key.
    ///
    /// The returned view borrows this redactor's policy snapshot. When its key
    /// is sensitive, it masks the complete value through
    /// [`RedactValue`](crate::RedactValue). Otherwise it delegates to the
    /// value's recursive redaction contracts.
    ///
    /// # Type Parameters
    ///
    /// * `'value` - Lifetime of the borrowed key and value.
    /// * `T` - Value type rendered or serialized through redaction.
    ///
    /// # Parameters
    ///
    /// * `key` - Field name used only for policy classification.
    /// * `value` - Value to render or serialize through the selected policy.
    ///
    /// # Returns
    ///
    /// A lazy keyed redaction view borrowing `key` and `value`.
    #[must_use = "format or serialize the returned keyed redaction view"]
    #[inline(always)]
    pub fn redact_keyed<'value, T: ?Sized>(
        &self,
        key: &'value str,
        value: &'value T,
    ) -> RedactedKeyedValue<'value, '_, T> {
        RedactedKeyedValue::new(key, value, &self.policy)
    }

    /// Redacts one value while bounding any allocated mask.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of the input and any borrowed redacted result.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    /// * `value` - Field value to redact when sensitive.
    /// * `max_bytes` - Maximum bytes allocated for a generated mask.
    ///
    /// # Returns
    ///
    /// Typed redacted text whose owned mask does not exceed `max_bytes`.
    #[cfg(feature = "http")]
    pub(crate) fn redact_bounded<'a>(
        &self,
        field: &str,
        value: &'a str,
        max_bytes: usize,
    ) -> RedactedText<'a> {
        let value = match self.policy.sensitivity_for(field) {
            Some(level) => {
                self.policy.masking().mask_bounded(level, value, max_bytes)
            }
            None => Cow::Borrowed(value),
        };
        RedactedText::new(value)
    }

    /// Creates a redacted copy of a text-keyed, mutable text-valued map.
    ///
    /// The source map is never modified. Its concrete collection type is
    /// preserved by cloning the collection before applying in-place redaction.
    ///
    /// # Type Parameters
    ///
    /// * `M` - Cloneable map-like collection returned after redaction.
    /// * `K` - Runtime key type used for field classification.
    /// * `V` - Mutable map-value type redacted in the cloned collection.
    ///
    /// # Parameters
    ///
    /// * `map` - Map whose values are classified by their corresponding keys.
    ///
    /// # Returns
    ///
    /// A map of the same type containing redacted values.
    #[must_use = "use the returned redacted map"]
    pub fn redact_map<M, K: ?Sized, V: ?Sized>(&self, map: &M) -> M
    where
        M: Clone + RedactMapValueMut<K, V>,
    {
        let mut redacted = map.clone();
        RedactMapValueMut::redact_map_in_place(&mut redacted, &self.policy);
        redacted
    }

    /// Redacts sensitive values of a text-keyed map in place.
    ///
    /// # Type Parameters
    ///
    /// * `M` - Mutable map-like collection type.
    /// * `K` - Runtime key type used for field classification.
    /// * `V` - Mutable map-value type redacted in place.
    ///
    /// # Parameters
    ///
    /// * `map` - Mutable map whose values are classified by their keys.
    #[inline(always)]
    pub fn redact_map_in_place<M, K: ?Sized, V: ?Sized>(&self, map: &mut M)
    where
        M: RedactMapValueMut<K, V> + ?Sized,
    {
        RedactMapValueMut::redact_map_in_place(map, &self.policy);
    }
}

impl Default for Redactor {
    /// Creates a redactor from the current global default policy snapshot.
    ///
    /// # Returns
    ///
    /// A redactor that is unaffected by later policy configuration attempts.
    #[inline(always)]
    fn default() -> Self {
        Self::new(RedactionPolicy::default())
    }
}
