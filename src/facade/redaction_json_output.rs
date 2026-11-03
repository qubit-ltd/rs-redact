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
/// The JSON string is syntactically complete whenever this value exists.
/// [`is_complete()`](Self::is_complete) reports whether the redaction library
/// observed degradation while producing it. An ordinary sensitivity mask is
/// successful redaction and does not make this result incomplete. Disabled
/// policy can expose source data. This status covers only behavior observable
/// by the redaction library; it cannot establish that a custom `Serialize`
/// implementation included every business field.
///
/// See [`Redactor::to_json_with_status`](crate::Redactor::to_json_with_status)
/// for an executable example covering complete output, successful degraded
/// output, and encoding failure.
///
/// # Examples
///
/// The result is returned by `Redactor::to_json_with_status` after serializing
/// a redacted domain view:
///
/// ```
/// #[cfg(feature = "derive")]
/// {
///     use qubit_redact::{Redact, RedactionPolicy, Redactor};
///
///     #[derive(Redact)]
///     #[redact(crate = qubit_redact)]
///     struct Login {
///         #[redact(level = "secret")]
///         password: String,
///     }
///
///     let output = Redactor::standard().to_json_with_status(&Login {
///         password: "raw-secret".into(),
///     })?;
///     assert_eq!(output.json(), r#"{"password":"<redacted>"}"#);
///     assert!(output.is_complete());
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionJsonOutput {
    /// Completed compact JSON produced within the configured output budget.
    json: String,
    /// Degradation observed by the library during this encoding.
    reasons: RedactionReasons,
}

impl RedactionJsonOutput {
    /// Creates a result from completed JSON and the observed degradation.
    ///
    /// # Parameters
    ///
    /// - `json`: Complete compact JSON string.
    /// - `reasons`: Degradation reasons observed while producing `json`.
    ///
    /// # Returns
    ///
    /// A JSON result retaining the supplied status metadata.
    pub(crate) fn new(json: String, reasons: RedactionReasons) -> Self {
        Self { json, reasons }
    }

    /// Borrows the completed compact JSON.
    ///
    /// # Returns
    ///
    /// The JSON string, which is syntactically complete and within the
    /// configured final output budget.
    #[must_use]
    pub fn json(&self) -> &str {
        &self.json
    }

    /// Consumes the result and returns its JSON, discarding status metadata.
    ///
    /// # Returns
    ///
    /// The completed compact JSON string. Any degradation reasons are
    /// discarded.
    #[must_use]
    pub fn into_json(self) -> String {
        self.json
    }

    /// Returns whether no library-observed degradation occurred.
    ///
    /// Ordinary sensitivity masking is complete. This method does not verify
    /// business-level completeness of custom serialization, and `false`
    /// does not mean that JSON encoding was incomplete.
    ///
    /// # Returns
    ///
    /// `true` when no degradation reason was recorded; otherwise `false`.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.reasons == RedactionReasons::empty()
    }

    /// Returns the set of observed degradation reasons.
    ///
    /// # Returns
    ///
    /// The reasons recorded while producing this JSON. An empty set means no
    /// library-observed degradation.
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
