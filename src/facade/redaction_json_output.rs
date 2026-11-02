// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Completed compact JSON and observed structured-redaction status.

use crate::RedactionReasons;

/// A completed JSON encoding and the degradation observed during redaction.
///
/// `json()` is always syntactically complete. `is_complete()` describes
/// whether the redaction library had to replace or omit data because of a
/// configured resource limit or formatter/JSON failure. Ordinary sensitivity
/// masks, explicit skips, conditional omissions, and disabled policy do not
/// imply degradation. Completeness covers only behavior observable by this
/// library; it cannot establish that a custom serializer included every
/// business field. Disabled policy may expose source data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionJsonOutput {
    json: String,
    reasons: RedactionReasons,
}

impl RedactionJsonOutput {
    pub(crate) fn new(json: String, reasons: RedactionReasons) -> Self {
        Self { json, reasons }
    }

    /// Borrows the completed compact JSON.
    #[must_use]
    pub fn json(&self) -> &str {
        &self.json
    }

    /// Consumes the result and returns its JSON, discarding status metadata.
    #[must_use]
    pub fn into_json(self) -> String {
        self.json
    }

    /// Returns whether no library-observed degradation occurred.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.reasons == RedactionReasons::empty()
    }

    /// Returns the set of observed degradation reasons.
    #[must_use]
    pub fn reasons(&self) -> RedactionReasons {
        self.reasons
    }
}
// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
