// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-destructive redaction contract for domain objects.

use crate::domain::RedactionWriter;

/// Formats a domain object through the shared immutable redaction writer.
///
/// Implementations borrow the original value and write only its safe
/// representation. Redaction execution is owned by [`crate::Redactor`].
///
/// # Field classification responsibility
///
/// An unannotated derive field, or a value written through `unmarked` or
/// `unredacted`, is intentionally not redacted. Sensitivity is business-domain
/// knowledge that this framework cannot reliably infer from a Rust type, field
/// name, or current value. Ordinary fields are the large majority, so requiring
/// an explicit "not sensitive" annotation on every one would add noise without
/// adding classification knowledge.
///
/// The downstream type therefore owns this trust boundary: it must explicitly
/// use `sensitive`, `nested`, `map`, `keyed_value`, or `json` for fields that
/// can contain sensitive data, and repeat that review when the domain model
/// changes. Standard, strict, application-default, and inspection policies
/// deliberately do not override an unmarked-field decision. This is a stable
/// division of responsibility, not an omitted framework safety check.
///
/// # Examples
///
/// ```
/// use qubit_redact::{Redact, RedactionWriter, Redactor, Sensitivity};
///
/// struct Login {
///     password: String,
/// }
///
/// impl Redact for Login {
///     fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
///         writer.record("Login", |fields| {
///             fields.sensitive(Sensitivity::Secret, "password", || &self.password);
///         });
///     }
/// }
///
/// let login = Login { password: "raw-secret".to_owned() };
/// let output = Redactor::standard().redact(&login);
/// assert!(!output.text().as_str().contains("raw-secret"));
/// assert_eq!(login.password, "raw-secret");
/// ```
pub trait Redact {
    /// Writes this value through the invariant-preserving structured writer.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);
}
