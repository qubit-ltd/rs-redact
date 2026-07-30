// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy fail-closed formatting for JSON stored as text.

use std::fmt::{
    self,
    Write as _,
};

use crate::{
    RedactionPolicy,
    text::internal::LogEscapeWriter,
};

use super::RedactedJson;
#[cfg(feature = "serde")]
use super::redact_json_text_in_place::redacted_json_text;

/// JSON text rendered with recursive object-key redaction.
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
    #[inline(always)]
    pub const fn new(
        text: &'text str,
        policy: &'policy RedactionPolicy,
    ) -> Self {
        Self { text, policy }
    }
}

impl fmt::Debug for RedactedJsonText<'_, '_> {
    /// Formats parsed redacted JSON or an opaque replacement for invalid text.
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
        match serde_json::from_str(self.text) {
            Ok(value) => fmt::Debug::fmt(
                &RedactedJson::new(&value, self.policy),
                formatter,
            ),
            Err(_) => fmt::Debug::fmt(
                self.policy
                    .masking()
                    .mask_opaque(crate::Sensitivity::Secret),
                formatter,
            ),
        }
    }
}

impl fmt::Display for RedactedJsonText<'_, '_> {
    /// Writes compact redacted JSON escaped for a plain-text log boundary.
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
        let mut writer = LogEscapeWriter::new(formatter);
        write!(&mut writer, "{self:?}")
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
