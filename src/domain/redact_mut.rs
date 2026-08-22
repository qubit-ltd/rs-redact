// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Explicit logical in-place redaction contract for domain objects.

use crate::RedactionPolicy;
use crate::Redactor;

/// Replaces sensitive field values inside a domain object.
///
/// This trait changes the logical value only. It does not zeroize released
/// allocations or affect aliases, existing copies, or borrowed backing data.
pub trait RedactMut {
    /// Redacts this object in place with an explicit policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy snapshot governing every mutation.
    fn redact_in_place_with(&mut self, policy: &RedactionPolicy);

    /// Redacts this object in place with the application-default policy.
    #[inline]
    fn redact_in_place(&mut self) {
        let redactor = Redactor::application_default();
        self.redact_in_place_with(redactor.policy());
    }

    /// Consumes and redacts this object with an explicit policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy snapshot governing every mutation.
    ///
    /// # Returns
    ///
    /// The logically redacted object.
    #[must_use]
    #[inline]
    fn into_redacted_with(mut self, policy: &RedactionPolicy) -> Self
    where
        Self: Sized,
    {
        self.redact_in_place_with(policy);
        self
    }

    /// Consumes and redacts this object with the application-default policy.
    ///
    /// # Returns
    ///
    /// The logically redacted object.
    #[must_use]
    #[inline]
    fn into_redacted(self) -> Self
    where
        Self: Sized,
    {
        let redactor = Redactor::application_default();
        self.into_redacted_with(redactor.policy())
    }

    /// Clones and redacts this object with an explicit policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy snapshot governing every mutation.
    ///
    /// # Returns
    ///
    /// A redacted clone while the original remains unchanged.
    #[must_use]
    #[inline]
    fn to_redacted_with(&self, policy: &RedactionPolicy) -> Self
    where
        Self: Clone + Sized,
    {
        self.clone().into_redacted_with(policy)
    }

    /// Clones and redacts this object with the application-default policy.
    ///
    /// # Returns
    ///
    /// A redacted clone while the original remains unchanged.
    #[must_use]
    #[inline]
    fn to_redacted(&self) -> Self
    where
        Self: Clone + Sized,
    {
        let redactor = Redactor::application_default();
        self.to_redacted_with(redactor.policy())
    }
}
