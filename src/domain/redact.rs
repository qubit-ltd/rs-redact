// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Non-destructive redaction contract for domain objects.

use crate::domain::RedactionWriter;

/// Formats a domain object through the shared immutable redaction writer.
///
/// Implementations borrow the original value and write only its safe
/// representation. Redaction execution is owned by [`crate::Redactor`].
pub trait Redact {
    /// Writes this value through the invariant-preserving structured writer.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);
}
