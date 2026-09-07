// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Domain-value and scalar-field redaction operations.

use std::fmt::Display;

use super::Redactor;
use crate::Redact;
use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionTextOutput;
use crate::runtime::runtime_session::RuntimeSession;

impl Redactor {
    /// Creates a lazy borrowed view with an owned snapshot of this policy.
    ///
    /// No source access or budget consumption occurs until the view is used.
    /// Formatting requires `Redact`. With the `serde` feature, a derived
    /// value's view serializes structurally when its fields support the
    /// required Serde adapters. Each use starts an independent execution.
    ///
    /// # Type Parameters
    ///
    /// - `'value`: Lifetime of the borrowed source value.
    /// - `T`: Source type; capabilities are checked when the view is used.
    ///
    /// # Parameters
    ///
    /// - `value`: Source retained by reference without evaluating it.
    ///
    /// # Returns
    ///
    /// A reusable borrowed view that owns this redactor’s policy snapshot.
    #[must_use]
    #[inline(always)]
    pub fn redact_view<'value, T: ?Sized>(&self, value: &'value T) -> crate::RedactedView<'value, T> {
        crate::RedactedView::new(value, self.clone())
    }

    /// Redacts one domain value into final text and an execution summary.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Domain type exposing structured redaction.
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed domain value visited within one fresh budget.
    ///
    /// # Returns
    ///
    /// Final redacted text and its execution summary, including any truncation
    /// or admission failure recorded while processing the value.
    #[must_use]
    #[inline]
    pub fn redact_text<T>(&self, value: &T) -> RedactionTextOutput
    where
        T: Redact + ?Sized,
    {
        let mut session = self.text_runtime();
        let _ = session.value(value);
        session.finish()
    }

    /// Inspects one domain value without rendering any field content.
    ///
    /// # Errors
    ///
    /// Returns an inconclusive result when structural or input admission
    /// prevents the complete domain value from being classified.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Domain type exposing structured redaction.
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed domain value to classify without rendering fields.
    ///
    /// # Returns
    ///
    /// A conclusive sensitivity inspection, or a value-free error containing
    /// resource usage and reasons why complete classification was unavailable.
    #[inline]
    pub fn inspect<T>(&self, value: &T) -> Result<RedactionInspection, RedactionInspectionError>
    where
        T: Redact + ?Sized,
    {
        let mut session = self.inspection_runtime();
        session.inspect(value);
        session.finish()
    }

    /// Redacts one scalar field through a complete one-item transaction.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Scalar formatter evaluated only when admission and masking
    ///   require it.
    ///
    /// # Parameters
    ///
    /// - `field`: Raw field key used for admission and classification.
    /// - `value`: Scalar whose formatting is deferred until required.
    ///
    /// # Returns
    ///
    /// Final redacted text and its execution summary, including any truncation
    /// or admission failure recorded while processing the value.
    #[must_use]
    #[inline]
    pub fn redact_field<T>(&self, field: &str, value: &T) -> RedactionTextOutput
    where
        T: Display + ?Sized,
    {
        let mut session = self.text_runtime();
        let _ = session.field(field, value);
        session.finish()
    }

    /// Inspects one scalar field without rendering its value.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionInspectionError`] when an input, structural, or key
    /// limit prevents a conclusive classification.
    ///
    /// # Parameters
    ///
    /// - `field`: Raw key used for admission and classification.
    /// - `value`: Source text counted for inspection without rendering it.
    ///
    /// # Returns
    ///
    /// A conclusive sensitivity inspection, or a value-free error containing
    /// resource usage and reasons why complete classification was unavailable.
    #[inline]
    pub fn inspect_field(&self, field: &str, value: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        session.inspect_field(field, value);
        session.finish()
    }
}
