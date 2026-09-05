// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Domain-value and scalar-field redaction operations.

use super::Redactor;
use crate::Redact;
use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionTextOutput;
use crate::runtime::runtime_session::RuntimeSession;

impl Redactor {
    /// Redacts one domain value into final text and an execution summary.
    #[must_use]
    pub fn redact_text<T>(&self, value: &T) -> RedactionTextOutput
    where
        T: Redact + ?Sized,
    {
        let mut session = self.text_runtime();
        let _ = session.value(value);
        session.finish()
    }

    /// Creates a lazy borrowed view with an owned snapshot of this policy.
    ///
    /// No source access or budget consumption occurs until the view is used.
    /// Formatting requires `Redact`; structural serialization requires
    /// `RedactSerialize`. Each use starts an independent execution.
    #[must_use]
    pub fn redact_view<'value, T: ?Sized>(&self, value: &'value T) -> crate::RedactedView<'value, T> {
        crate::RedactedView::new(value, self.clone())
    }

    /// Inspects one domain value without rendering any field content.
    ///
    /// # Errors
    ///
    /// Returns an inconclusive result when structural or input admission
    /// prevents the complete domain value from being classified.
    pub fn inspect<T>(&self, value: &T) -> Result<RedactionInspection, RedactionInspectionError>
    where
        T: Redact + ?Sized,
    {
        let mut session = self.inspection_runtime();
        session.inspect(value);
        session.finish()
    }

    /// Redacts one scalar field through a complete one-item transaction.
    #[must_use]
    pub fn redact_field<T>(&self, field: &str, value: &T) -> RedactionTextOutput
    where
        T: std::fmt::Display + ?Sized,
    {
        let mut session = self.text_runtime();
        let _ = session.field(field, value);
        session.finish()
    }

    /// Inspects one scalar field without rendering its value.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionInspectionError`] when the shared input or
    /// structural budget prevents a conclusive classification.
    pub fn inspect_field(&self, field: &str, value: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        session.inspect_field(field, value);
        session.finish()
    }
}
