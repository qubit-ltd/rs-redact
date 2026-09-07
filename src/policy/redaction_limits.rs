// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable structural limits used by redaction.

use qubit_budget::StructureLimits;
#[cfg(feature = "json")]
use qubit_budget::json::JsonValueLimits;

use super::RedactionLimitsBuilder;

/// Structural and JSON limits for one redaction operation.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionLimits;
///
/// let mut builder = RedactionLimits::builder();
/// builder.max_output_bytes(128);
/// let limits = builder.build();
/// assert_eq!(limits.max_output_bytes(), 128);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionLimits {
    /// Maximum source bytes admitted for inspection.
    max_input_bytes: usize,
    /// Maximum safe bytes retained in output.
    max_output_bytes: usize,
    /// Maximum logical scalar bytes passed to a Serde serializer.
    #[cfg(feature = "serde")]
    max_serde_payload_bytes: usize,
    /// Structural limits shared by domain and format traversal.
    domain: StructureLimits,
    /// JSON-specific structural and payload limits.
    #[cfg(feature = "json")]
    json: JsonValueLimits,
}

impl RedactionLimits {
    /// Creates a builder initialized with the standard redaction limits.
    ///
    /// # Returns
    ///
    /// A mutable builder initialized with finite standard resource ceilings.
    #[must_use]
    #[inline(always)]
    pub fn builder() -> RedactionLimitsBuilder {
        RedactionLimitsBuilder::default()
    }

    /// Creates a builder from an immutable limit snapshot.
    ///
    /// # Parameters
    ///
    /// - `base`: Snapshot whose configured ceilings are copied.
    ///
    /// # Returns
    ///
    /// A mutable builder preserving every ceiling of the supplied snapshot.
    #[must_use]
    #[inline(always)]
    pub(crate) fn builder_from(base: &Self) -> RedactionLimitsBuilder {
        RedactionLimitsBuilder::from_limits(base)
    }

    /// Creates a snapshot from the builder's complete component state.
    ///
    /// # Parameters
    ///
    /// - `max_input_bytes`: Cumulative source-byte ceiling.
    /// - `max_output_bytes`: Retained output-byte ceiling.
    /// - `max_serde_payload_bytes`: Logical scalar-byte ceiling, with Serde
    ///   enabled.
    /// - `domain`: Structural admission ceilings shared by the transaction.
    /// - `json`: JSON-specific ceilings, with JSON enabled.
    ///
    /// # Returns
    ///
    /// A snapshot retaining all supplied ceilings; policy construction
    /// validates it.
    #[must_use]
    #[inline(always)]
    pub(super) fn from_parts(
        max_input_bytes: usize,
        max_output_bytes: usize,
        #[cfg(feature = "serde")] max_serde_payload_bytes: usize,
        domain: StructureLimits,
        #[cfg(feature = "json")] json: JsonValueLimits,
    ) -> Self {
        Self {
            max_input_bytes,
            max_output_bytes,
            #[cfg(feature = "serde")]
            max_serde_payload_bytes,
            domain,
            #[cfg(feature = "json")]
            json,
        }
    }

    /// Returns the maximum source bytes one transaction may inspect.
    ///
    /// # Returns
    ///
    /// Cumulative source bytes admitted by one transaction.
    #[must_use]
    #[inline(always)]
    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    /// Returns the maximum safe output bytes one transaction may retain.
    ///
    /// # Returns
    ///
    /// Maximum final output bytes retained by one transaction.
    #[must_use]
    #[inline(always)]
    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    /// Returns the logical scalar payload limit for a structured Serde scope.
    ///
    /// Counts UTF-8 strings/chars, byte slices, and scalar representations.
    /// Excludes static field names, container framing, and serializer escaping.
    /// A caller-owned serializer controls its final encoded byte length;
    /// `Redactor::to_json` additionally enforces `max_output_bytes`
    /// when the `json` feature is enabled. The default is 16 KiB; zero is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```
    /// use qubit_redact::RedactionLimits;
    /// let mut builder = RedactionLimits::builder();
    /// builder.max_serde_payload_bytes(4).max_output_bytes(32);
    /// assert_eq!(builder.build().max_serde_payload_bytes(), 4);
    /// ```
    ///
    /// # Returns
    ///
    /// Logical scalar bytes admitted by one structured Serde scope.
    #[cfg(feature = "serde")]
    #[must_use]
    #[inline(always)]
    pub const fn max_serde_payload_bytes(&self) -> usize {
        self.max_serde_payload_bytes
    }

    /// Returns the maximum nested structural depth.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` is the configured ceiling; `None` disables this limit.
    #[must_use]
    #[inline(always)]
    pub const fn max_depth(&self) -> Option<usize> {
        self.domain.max_depth()
    }

    /// Returns the maximum number of structural nodes.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` is the configured ceiling; `None` disables this limit.
    #[must_use]
    #[inline(always)]
    pub const fn max_nodes(&self) -> Option<usize> {
        self.domain.max_nodes()
    }

    /// Returns the cumulative item allowance shared by transaction collections.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` is the configured ceiling; `None` disables this limit.
    #[must_use]
    #[inline(always)]
    pub const fn max_collection_items(&self) -> Option<usize> {
        self.domain.max_sequence_items()
    }

    /// Returns the maximum raw UTF-8 length of a domain field or classification
    /// key, checked before normalization and value access. JSON keys also have
    /// their independent JSON admission limits.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` bounds raw key bytes; `None` disables this limit.
    #[must_use]
    #[inline(always)]
    pub const fn max_key_bytes(&self) -> Option<usize> {
        self.domain.max_key_bytes()
    }

    /// Returns the maximum JSON nesting depth.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` is the configured ceiling; `None` disables this limit.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_depth(&self) -> Option<usize> {
        self.json.max_depth()
    }

    /// Returns the maximum number of JSON nodes.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` is the configured ceiling; `None` disables this limit.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_nodes(&self) -> Option<usize> {
        self.json.max_nodes()
    }

    /// Returns the maximum number of items in one JSON collection.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` is the configured ceiling; `None` disables this limit.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_collection_items(&self) -> Option<usize> {
        self.json.max_sequence_items()
    }

    /// Returns the maximum JSON object-key length.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` is the configured ceiling; `None` disables this limit.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_key_bytes(&self) -> Option<usize> {
        self.json.max_key_bytes()
    }

    /// Returns the maximum JSON string length.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` is the configured ceiling; `None` disables this limit.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_string_bytes(&self) -> Option<usize> {
        self.json.max_string_bytes()
    }

    /// Returns the maximum JSON number representation length.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` is the configured ceiling; `None` disables this limit.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_number_bytes(&self) -> Option<usize> {
        self.json.max_number_bytes()
    }

    /// Returns the cumulative JSON payload-byte maximum.
    ///
    /// # Returns
    ///
    /// `Some(maximum)` is the configured ceiling; `None` disables this limit.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_payload_bytes(&self) -> Option<usize> {
        self.json.max_payload_bytes()
    }

    /// Returns the internal structural limits for transaction construction.
    ///
    /// # Returns
    ///
    /// The shared immutable structural admission ceilings.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn structural_limits(&self) -> StructureLimits {
        self.domain
    }

    /// Returns the internal JSON limits for transaction construction.
    ///
    /// # Returns
    ///
    /// The immutable JSON-specific admission ceilings.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub(crate) const fn json_limits(&self) -> JsonValueLimits {
        self.json
    }

    /// Validates limits whose values would otherwise reach collection
    /// allocation code during transaction rendering.
    ///
    /// # Errors
    ///
    /// Returns [`super::PolicyError::OutputLimitTooLarge`] when the output
    /// ceiling exceeds the maximum addressable Rust collection capacity.
    /// With `serde`, an oversized logical payload ceiling returns
    /// `PolicyError::SerdePayloadLimitTooLarge`.
    ///
    /// # Returns
    ///
    /// Success when output and enabled Serde payload ceilings fit Rust
    /// allocation limits.
    pub(crate) fn validate(&self) -> Result<(), super::PolicyError> {
        if self.max_output_bytes > isize::MAX as usize {
            return Err(super::PolicyError::OutputLimitTooLarge {
                maximum: self.max_output_bytes,
            });
        }
        #[cfg(feature = "serde")]
        if self.max_serde_payload_bytes > isize::MAX as usize {
            return Err(super::PolicyError::SerdePayloadLimitTooLarge {
                maximum: self.max_serde_payload_bytes,
            });
        }
        Ok(())
    }
}

impl Default for RedactionLimits {
    /// Builds the immutable standard limit snapshot.
    ///
    /// # Returns
    ///
    /// The standard immutable resource limits produced by the default builder.
    #[inline(always)]
    fn default() -> Self {
        Self::builder().build()
    }
}
