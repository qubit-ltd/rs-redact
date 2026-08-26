// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Generic URI redaction operations.

use super::Redactor;
use crate::RedactionInspectionResult;
use crate::RedactionTextOutput;

impl Redactor {
    /// Redacts a URI through one completed batch transaction.
    #[must_use]
    pub fn redact_uri(&self, input: &str) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_uri(input);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one URI without rendering it.
    pub fn inspect_uri(&self, input: &str) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::uri::inspection::inspect_uri(&mut session, input);
        session.finish()
    }
}
