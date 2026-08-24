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
/// # Warning
///
/// An unannotated derive field, or a value written through `unmarked` or
/// `unredacted`, is an explicit trust boundary owned by the downstream type.
/// Standard, strict, application-default, and inspection policies do not infer
/// sensitivity from that field's name or contents and do not upgrade it later.
/// Review every field whenever a domain type changes. Fields that can contain
/// sensitive data must explicitly use an appropriate capability such as
/// `sensitive`, `nested`, `map`, or `json`.
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
