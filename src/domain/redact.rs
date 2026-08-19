// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-destructive redaction contract for domain objects.
// qubit-style: allow multiple-public-types

use crate::RedactionOutput;
use crate::Redactor;
use crate::domain::RedactionWriter;

/// Formats a domain object through an explicit immutable redaction policy.
///
/// Implementations must write only the redacted representation through
/// [`Self::write_redacted`]. The original object remains unchanged.
/// Domain owners remain responsible for deciding which fields are sensitive
/// and for selecting the redaction boundary. This trait does not infer that a
/// newly added field needs redaction.
///
/// # Warning
///
/// For derive implementations, an unannotated field is deliberately emitted
/// without redaction. Every sensitive field must be explicitly annotated with
/// `#[redact(...)]`; `#[redact(skip)]` also deliberately bypasses redaction.
///
/// Pure domain formatting consumes output bytes and domain structure budget,
/// but never consumes diagnostic input bytes. An adapter that inspects encoded
/// input, such as JSON or HTTP, must charge the exact input size at its adapter
/// boundary. Implementations must enter the object before inspecting fields,
/// admit every field before reading or formatting it. The writer emits the
/// structural truncation marker when admission fails. Sensitive fields must use
/// fixed or policy-derived safe values without invoking their original `Debug`
/// or `Display` implementation. Output is bounded by the library, but arbitrary
/// user formatting logic may still perform its own computation or allocation.
///
/// Every implementation must define its redaction behavior explicitly:
///
/// ```compile_fail
/// use qubit_redact::Redact;
///
/// struct MissingRedactionContract;
///
/// impl Redact for MissingRedactionContract {}
/// ```
pub trait Redact {
    /// Writes this value through the invariant-preserving structured writer.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);

    /// Redacts this value with the current application-default redactor.
    ///
    /// # Returns
    ///
    /// The completed transaction output.
    #[inline(always)]
    #[must_use]
    fn redacted(&self) -> RedactionOutput
    where
        Self: Sized,
    {
        Redactor::application_default().redact(self)
    }

    /// Redacts this value using an explicit redactor.
    ///
    /// # Parameters
    ///
    /// * `redactor` - Explicit immutable policy snapshot and execution entry.
    ///
    /// # Returns
    ///
    /// The completed transaction output.
    #[inline(always)]
    #[must_use]
    fn redacted_with(&self, redactor: &Redactor) -> RedactionOutput
    where
        Self: Sized,
    {
        redactor.redact(self)
    }
}
