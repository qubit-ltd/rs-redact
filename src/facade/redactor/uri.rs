// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Generic URI redaction operations.

use super::Redactor;
use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionTextOutput;

impl Redactor {
    /// Redacts a URI through one completed text transaction.
    #[must_use]
    pub fn redact_uri(&self, input: &str) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.uri(|uri| {
            let _ = uri.value(input);
        });
        session.finish()
    }

    /// Inspects one URI without rendering it.
    pub fn inspect_uri(&self, input: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        crate::formats::uri::inspection::inspect_uri(&mut session, input);
        session.finish()
    }
}
