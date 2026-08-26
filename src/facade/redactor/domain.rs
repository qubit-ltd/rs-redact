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
use crate::RedactionInspectionResult;
use crate::RedactionTextOutput;
use crate::runtime::runtime_session::RuntimeSession;

impl Redactor {
    /// Redacts one domain value into final text and an execution summary.
    #[must_use]
    pub fn redact<T>(&self, value: &T) -> RedactionTextOutput
    where
        T: Redact + ?Sized,
    {
        let mut batch = self.batch();
        let handle = batch.redact_value(value);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one domain value without rendering any field content.
    ///
    /// # Errors
    ///
    /// Returns an inconclusive result when structural or input admission
    /// prevents the complete domain value from being classified.
    pub fn inspect<T>(&self, value: &T) -> RedactionInspectionResult
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
        let mut batch = self.batch();
        let handle = batch.redact_field(field, value);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one scalar field without rendering its value.
    pub fn inspect_field(&self, field: &str, value: &str) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        session.inspect_field(field, value);
        session.finish()
    }
}
