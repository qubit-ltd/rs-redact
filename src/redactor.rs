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
    RedactedText,
    RedactionPolicy,
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

    /// Creates a redacted copy of a string-keyed, string-valued map.
    ///
    /// The source map is never modified. Its concrete collection type is
    /// preserved through `FromIterator`.
    ///
    /// # Parameters
    ///
    /// * `map` - Map whose values are classified by their corresponding keys.
    ///
    /// # Returns
    ///
    /// A map of the same type containing cloned keys and redacted values.
    #[must_use = "use the returned redacted map"]
    pub fn redact_map<M>(&self, map: &M) -> M
    where
        for<'a> &'a M: IntoIterator<Item = (&'a String, &'a String)>,
        M: FromIterator<(String, String)>,
    {
        map.into_iter()
            .map(|(key, value)| {
                (key.clone(), self.redact(key, value).into_owned())
            })
            .collect()
    }

    /// Redacts sensitive values of a string-keyed map in place.
    ///
    /// Borrowed results leave their source entries untouched. Only owned mask
    /// results replace map values, avoiding simultaneous borrowing and
    /// assignment of the same entry.
    ///
    /// # Parameters
    ///
    /// * `map` - Mutable map whose values are classified by their keys.
    pub fn redact_map_in_place<M: ?Sized>(&self, map: &mut M)
    where
        for<'a> &'a mut M: IntoIterator<Item = (&'a String, &'a mut String)>,
    {
        for (key, value) in map {
            if let Cow::Owned(redacted) = self.redact(key, value).into_inner() {
                *value = redacted;
            }
        }
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
