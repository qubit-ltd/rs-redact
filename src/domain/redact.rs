// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-destructive redaction contract for domain objects.
// qubit-style: allow multiple-public-types

use crate::RedactionPolicy;
use crate::domain::Redacted;
use crate::domain::RedactionWriter;

/// Writes the unquoted safe marker for a domain branch that was not admitted.
pub struct DomainTruncated;

impl std::fmt::Debug for DomainTruncated {
    /// Writes the complete unquoted structural truncation marker.
    #[inline(always)]
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<truncated>")
    }
}

/// Formats a domain object through an explicit immutable redaction policy.
///
/// Implementations must write only the redacted representation through
/// [`Self::write_redacted`]. The original object remains unchanged.
/// Domain owners remain responsible for deciding which fields are sensitive
/// and for selecting the redaction boundary. This trait does not infer that a
/// newly added field needs redaction.
///
/// Pure domain formatting consumes output bytes and domain structure budget,
/// but never consumes diagnostic input bytes. An adapter that inspects encoded
/// input, such as JSON or HTTP, must charge the exact input size at its adapter
/// boundary. Implementations must enter the object before inspecting fields,
/// admit every field before reading or formatting it, and use
/// [`DomainTruncated`] when admission fails. Sensitive fields must use fixed or
/// policy-derived safe values without invoking their original `Debug` or
/// `Display` implementation. Output is bounded by the library, but arbitrary
/// user formatting logic may still perform its own computation or allocation.
pub trait Redact {
    /// Writes this value through the invariant-preserving structured writer.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.literal("<truncated>");
    }

    /// Creates a borrowed view using a snapshot of the current default policy.
    ///
    /// # Returns
    ///
    /// A lazy redacted view borrowing this object and owning its policy
    /// snapshot.
    #[inline(always)]
    #[must_use]
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
    #[must_use]
    fn redacted_with(&self, policy: &RedactionPolicy) -> Redacted<'_, Self>
    where
        Self: Sized,
    {
        Redacted::new(self, policy.clone())
    }
}

/// Writes one domain value into a formatter through a shared structured
/// session.
pub(crate) fn write_redacted_to_formatter<T: Redact + ?Sized>(
    value: &T,
    session: &mut crate::RedactionSession<'_>,
    formatter: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    let mut writer = RedactionWriter::new(session);
    value.write_redacted(&mut writer);
    formatter.write_str(&writer.finish())
}
