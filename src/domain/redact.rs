// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-destructive redaction contract for domain objects.

use std::fmt::{
    self,
    Formatter,
};

use crate::{
    Redacted,
    RedactionPolicy,
};

/// Formats a domain object through an explicit immutable redaction policy.
///
/// Implementations must write only the redacted representation from
/// [`Self::fmt_redacted`]. The original object remains unchanged.
pub trait Redact {
    /// Creates a borrowed view using a snapshot of the current default policy.
    ///
    /// # Returns
    ///
    /// A lazy redacted view borrowing this object and owning its policy
    /// snapshot.
    #[inline(always)]
    fn redacted(&self) -> Redacted<'_, Self>
    where
        Self: Sized,
    {
        Redacted::new(self, RedactionPolicy::default())
    }

    /// Creates a borrowed view using a snapshot of `policy`.
    ///
    /// # Parameters
    ///
    /// * `policy` - Policy to clone into the returned view.
    ///
    /// # Returns
    ///
    /// A lazy redacted view borrowing this object and owning the cloned policy.
    #[inline(always)]
    fn redacted_with(&self, policy: &RedactionPolicy) -> Redacted<'_, Self>
    where
        Self: Sized,
    {
        Redacted::new(self, policy.clone())
    }

    /// Writes this object's redacted debug representation.
    ///
    /// Implementations should honor the formatting flags carried by
    /// `formatter`, including alternate pretty formatting. Sensitive fields
    /// must not invoke their original `Debug` or `Display` implementations.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy snapshot governing this representation.
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for the complete redacted representation.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter cannot accept the
    /// complete representation.
    #[doc(hidden)]
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result;
}
