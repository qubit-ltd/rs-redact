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
use crate::text::internal::BoundedLogEscapeWriter;

/// JSON text rendered with recursive object-key redaction.
///
/// [`fmt::Debug`] and [`fmt::Display`] are diagnostic boundaries: they reject
/// text larger than the policy diagnostic input budget before parsing it and
/// apply the policy output budget. Explicit mutation and Serde serialization
/// preserve complete JSON instead.
#[must_use = "format or serialize the redacted JSON text view"]
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
    pub const fn new(text: &'text str, policy: &'policy RedactionPolicy) -> Self {
        Self { text, policy }
    }

    /// Reports whether diagnostic formatting must refuse the raw input.
    ///
    /// # Returns
    ///
    /// True when the text exceeds the policy input limit.
    #[inline(always)]
    const fn exceeds_diagnostic_input_budget(&self) -> bool {
        self.text.len() > self.policy.limits().diagnostic_event().max_input_bytes()
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
                    let _ = write!(&mut writer, "{:#?}", RedactedJson::new(&value, self.policy),);
                }
                Ok(value) => {
                    let _ = write!(&mut writer, "{:?}", RedactedJson::new(&value, self.policy),);
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

mod session_view {
    use std::fmt;

    use crate::RedactedJsonText;
    use crate::RedactionSession;
    use crate::Sensitivity;
    use crate::policy::OutputCharge;

    /// A nested JSON text view that accounts against an existing diagnostic
    /// session.
    #[must_use = "format the nested redacted JSON text view"]
    pub struct RedactedJsonTextSession<'text, 'session, 'policy> {
        text: &'text str,
        session: &'session RedactionSession<'policy>,
    }

    impl<'text, 'session, 'policy> RedactedJsonTextSession<'text, 'session, 'policy> {
        /// Creates a JSON text view borrowing an existing diagnostic session.
        #[inline(always)]
        pub fn new(text: &'text str, session: &'session RedactionSession<'policy>) -> Self {
            Self { text, session }
        }

        /// Renders the nested JSON text while consuming session input and
        /// output.
        fn render(&self) -> String {
            let policy = self.session.policy();
            if !self.session.consume_input(self.text.len()) {
                return self.fallback();
            }
            let mut rendered = String::new();
            if fmt::write(
                &mut rendered,
                format_args!("{:?}", RedactedJsonText::new(self.text, policy),),
            )
            .is_err()
            {
                return self.fallback();
            }
            let fallback = policy.masking().mask_opaque(Sensitivity::Secret);
            match self
                .session
                .charge_output_or_fallback(rendered.len(), fallback.len())
            {
                OutputCharge::Complete => rendered,
                OutputCharge::Fallback => fallback.to_owned(),
                OutputCharge::Exhausted => String::new(),
            }
        }

        /// Charges one opaque fallback or returns no bytes after exhaustion.
        fn fallback(&self) -> String {
            let fallback = self
                .session
                .policy()
                .masking()
                .mask_opaque(Sensitivity::Secret);
            match self
                .session
                .charge_output_or_fallback(fallback.len(), fallback.len())
            {
                OutputCharge::Complete => fallback.to_owned(),
                OutputCharge::Fallback | OutputCharge::Exhausted => String::new(),
            }
        }
    }

    impl fmt::Debug for RedactedJsonTextSession<'_, '_, '_> {
        /// Formats nested JSON text through the shared session.
        #[inline]
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.render())
        }
    }

    impl fmt::Display for RedactedJsonTextSession<'_, '_, '_> {
        /// Escapes nested JSON text through the shared session.
        #[inline]
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.render())
        }
    }
}

pub use session_view::RedactedJsonTextSession;

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
