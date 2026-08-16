// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy fail-closed formatting for JSON stored as text.

use std::fmt;
use std::fmt::Write as _;

use super::RedactedJson;
use super::redact_json_text_in_place::redacted_json_text;
use crate::LogOutputLimit;
use crate::RedactionPolicy;
use crate::Sensitivity;
use crate::output::internal::BoundedLogEscapeWriter;

/// JSON text rendered with recursive object-key redaction.
///
/// [`fmt::Debug`] and [`fmt::Display`] are diagnostic boundaries: they reject
/// text larger than the policy diagnostic input budget before parsing it and
/// apply the policy output budget. Explicit mutation and Serde serialization
/// preserve complete JSON instead.
pub struct RedactedJsonText<'text, 'policy> {
    /// Original JSON text borrowed without cloning.
    text: &'text str,
    /// Policy used to classify every parsed object key.
    policy: &'policy RedactionPolicy,
}

impl<'text, 'policy> RedactedJsonText<'text, 'policy> {
    /// Creates a lazy redacted view over text expected to contain JSON.
    ///
    /// # Parameters
    ///
    /// * text - JSON text borrowed without parsing.
    /// * policy - Immutable policy used to classify parsed object keys.
    ///
    /// # Returns
    ///
    /// A borrowed fail-closed JSON text view.
    #[must_use]
    pub const fn new(
        text: &'text str,
        policy: &'policy RedactionPolicy,
    ) -> Self {
        Self { text, policy }
    }

    /// Reports whether diagnostic formatting must refuse the raw input.
    ///
    /// # Returns
    ///
    /// True when the text exceeds the policy input limit.
    #[inline(always)]
    const fn exceeds_diagnostic_input_budget(&self) -> bool {
        self.text.len()
            > self.policy.limits().diagnostic_event().max_input_bytes()
    }

    /// Returns the configured opaque replacement for unsafe JSON text.
    ///
    /// # Returns
    ///
    /// An opaque Secret-sensitivity marker.
    #[inline(always)]
    fn opaque_secret(&self) -> &str {
        self.policy.masking().mask_opaque(Sensitivity::Secret)
    }

    /// Produces compact redacted JSON for a diagnostic rendering.
    ///
    /// # Returns
    ///
    /// Compact redacted JSON, or an opaque marker when the input is unsafe.
    fn diagnostic_json_text(&self) -> String {
        if self.exceeds_diagnostic_input_budget() {
            return self.opaque_secret().to_owned();
        }
        redacted_json_text(self.text, self.policy)
    }
}

impl fmt::Debug for RedactedJsonText<'_, '_> {
    /// Formats parsed redacted JSON or an opaque replacement for unsafe text.
    ///
    /// Output that exceeds the diagnostic budget ends in the log truncation
    /// marker.
    ///
    /// # Parameters
    ///
    /// * formatter - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for a safe representation.
    ///
    /// # Errors
    ///
    /// Returns a formatting error when the destination rejects output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut writer = BoundedLogEscapeWriter::new(LogOutputLimit::from(
            self.policy.limits().diagnostic_event(),
        ));
        if self.exceeds_diagnostic_input_budget() {
            let _ = write!(&mut writer, "{:?}", self.opaque_secret());
        } else {
            match serde_json::from_str(self.text) {
                Ok(value) if formatter.alternate() => {
                    let _ = write!(
                        &mut writer,
                        "{:#?}",
                        RedactedJson::new(&value, self.policy),
                    );
                }
                Ok(value) => {
                    let _ = write!(
                        &mut writer,
                        "{:?}",
                        RedactedJson::new(&value, self.policy),
                    );
                }
                Err(_) => {
                    let _ = write!(&mut writer, "{:?}", self.opaque_secret());
                }
            }
        }
        formatter.write_str(&writer.finish())
    }
}

impl fmt::Display for RedactedJsonText<'_, '_> {
    /// Writes compact redacted JSON for a bounded plain-text log boundary.
    ///
    /// Complete valid input that fits both diagnostic budgets produces compact
    /// valid JSON. Rejected input produces the opaque Secret mask; output that
    /// exceeds its budget ends in the log truncation marker and is not JSON.
    ///
    /// # Parameters
    ///
    /// * formatter - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for safe log output.
    ///
    /// # Errors
    ///
    /// Returns a formatting error when the destination rejects output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut writer = BoundedLogEscapeWriter::new(LogOutputLimit::from(
            self.policy.limits().diagnostic_event(),
        ));
        let _ = writer.write_str(&self.diagnostic_json_text());
        formatter.write_str(&writer.finish())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for RedactedJsonText<'_, '_> {
    /// Serializes compact redacted JSON while preserving the outer string
    /// shape.
    ///
    /// # Type Parameters
    ///
    /// * S - Destination serializer type.
    ///
    /// # Parameters
    ///
    /// * serializer - Destination serde serializer.
    ///
    /// # Returns
    ///
    /// The destination serializer result.
    ///
    /// # Errors
    ///
    /// Returns the destination serializer error unchanged.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&redacted_json_text(self.text, self.policy))
    }
}
