// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable structural limits used by redaction.
// qubit-style: allow multiple-public-types

use qubit_budget::StructureLimits;
#[cfg(feature = "json")]
use qubit_budget::json::JsonValueLimits;

/// Mutable construction state for [`RedactionLimits`].
#[derive(Debug, Clone, Copy)]
pub struct RedactionLimitsBuilder {
    /// Draft maximum source bytes admitted for inspection.
    max_input_bytes: usize,
    /// Draft maximum safe bytes retained in output.
    max_output_bytes: usize,
    /// Draft structural limits shared by domain and format traversal.
    domain: StructureLimits,
    /// Draft JSON-specific structural and payload limits.
    #[cfg(feature = "json")]
    json: JsonValueLimits,
}

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
    /// Structural limits shared by domain and format traversal.
    domain: StructureLimits,
    /// JSON-specific structural and payload limits.
    #[cfg(feature = "json")]
    json: JsonValueLimits,
}

impl RedactionLimits {
    /// Creates a builder initialized with the standard redaction limits.
    #[must_use]
    pub fn builder() -> RedactionLimitsBuilder {
        RedactionLimitsBuilder::default()
    }

    /// Creates a builder from an immutable limit snapshot.
    #[must_use]
    pub(crate) fn builder_from(base: &Self) -> RedactionLimitsBuilder {
        RedactionLimitsBuilder {
            max_input_bytes: base.max_input_bytes,
            max_output_bytes: base.max_output_bytes,
            domain: base.domain,
            #[cfg(feature = "json")]
            json: base.json,
        }
    }

    /// Returns the internal structural limits for transaction construction.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn structural_limits(&self) -> StructureLimits {
        self.domain
    }

    /// Returns the maximum source bytes one transaction may inspect.
    #[must_use]
    #[inline(always)]
    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    /// Returns the maximum safe output bytes one transaction may retain.
    #[must_use]
    #[inline(always)]
    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    /// Returns the maximum nested structural depth.
    #[must_use]
    #[inline(always)]
    pub const fn max_depth(&self) -> Option<usize> {
        self.domain.max_depth()
    }

    /// Returns the maximum number of structural nodes.
    #[must_use]
    #[inline(always)]
    pub const fn max_nodes(&self) -> Option<usize> {
        self.domain.max_nodes()
    }

    /// Returns the shared maximum item count for one sequence or map.
    #[must_use]
    #[inline(always)]
    pub const fn max_collection_items(&self) -> Option<usize> {
        self.domain.max_sequence_items()
    }

    /// Returns the maximum structural key length.
    #[must_use]
    #[inline(always)]
    pub const fn max_key_bytes(&self) -> Option<usize> {
        self.domain.max_key_bytes()
    }

    /// Validates limits whose values would otherwise reach collection
    /// allocation code during transaction rendering.
    ///
    /// # Errors
    ///
    /// Returns [`super::PolicyError::OutputLimitTooLarge`] when the output
    /// ceiling exceeds the maximum addressable Rust collection capacity.
    pub(crate) fn validate(&self) -> Result<(), super::PolicyError> {
        if self.max_output_bytes > isize::MAX as usize {
            return Err(super::PolicyError::OutputLimitTooLarge {
                maximum: self.max_output_bytes,
            });
        }
        Ok(())
    }

    /// Returns the internal JSON limits for transaction construction.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub(crate) const fn json_limits(&self) -> JsonValueLimits {
        self.json
    }

    /// Returns the maximum JSON nesting depth.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_depth(&self) -> Option<usize> {
        self.json.max_depth()
    }

    /// Returns the maximum number of JSON nodes.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_nodes(&self) -> Option<usize> {
        self.json.max_nodes()
    }

    /// Returns the maximum number of items in one JSON collection.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_collection_items(&self) -> Option<usize> {
        self.json.max_sequence_items()
    }

    /// Returns the maximum JSON object-key length.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_key_bytes(&self) -> Option<usize> {
        self.json.max_key_bytes()
    }

    /// Returns the maximum JSON string length.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_string_bytes(&self) -> Option<usize> {
        self.json.max_string_bytes()
    }

    /// Returns the maximum JSON number representation length.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_number_bytes(&self) -> Option<usize> {
        self.json.max_number_bytes()
    }

    /// Returns the cumulative JSON payload-byte maximum.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn max_json_payload_bytes(&self) -> Option<usize> {
        self.json.max_payload_bytes()
    }
}

impl RedactionLimitsBuilder {
    /// Sets the maximum source bytes one transaction may inspect.
    pub fn max_input_bytes(&mut self, maximum: usize) -> &mut Self {
        self.max_input_bytes = maximum;
        self
    }

    /// Sets the maximum safe output bytes one transaction may retain.
    pub fn max_output_bytes(&mut self, maximum: usize) -> &mut Self {
        self.max_output_bytes = maximum;
        self
    }

    /// Sets the maximum nested domain depth.
    pub fn max_depth(&mut self, maximum: usize) -> &mut Self {
        self.domain = self.domain.into_builder().max_depth(maximum).build();
        self
    }

    /// Sets the maximum admitted domain nodes.
    pub fn max_nodes(&mut self, maximum: usize) -> &mut Self {
        self.domain = self.domain.into_builder().max_nodes(maximum).build();
        self
    }

    /// Sets the maximum items admitted from one collection.
    pub fn max_collection_items(&mut self, maximum: usize) -> &mut Self {
        self.domain = self
            .domain
            .into_builder()
            .max_sequence_items(maximum)
            .max_map_entries(maximum)
            .build();
        self
    }

    /// Sets the maximum structural key length.
    pub fn max_key_bytes(&mut self, maximum: usize) -> &mut Self {
        self.domain = self.domain.into_builder().max_key_bytes(maximum).build();
        self
    }

    /// Sets the maximum JSON nesting depth.
    #[cfg(feature = "json")]
    pub fn max_json_depth(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_depth(maximum).build();
        self
    }

    /// Sets the maximum number of JSON nodes.
    #[cfg(feature = "json")]
    pub fn max_json_nodes(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_nodes(maximum).build();
        self
    }

    /// Sets the maximum number of items in one JSON collection.
    #[cfg(feature = "json")]
    pub fn max_json_collection_items(&mut self, maximum: usize) -> &mut Self {
        self.json = self
            .json
            .into_builder()
            .max_sequence_items(maximum)
            .max_map_entries(maximum)
            .build();
        self
    }

    /// Sets the maximum JSON object-key length.
    #[cfg(feature = "json")]
    pub fn max_json_key_bytes(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_key_bytes(maximum).build();
        self
    }

    /// Sets the maximum JSON string length.
    #[cfg(feature = "json")]
    pub fn max_json_string_bytes(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_string_bytes(maximum).build();
        self
    }

    /// Sets the maximum JSON number representation length.
    #[cfg(feature = "json")]
    pub fn max_json_number_bytes(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_number_bytes(maximum).build();
        self
    }

    /// Sets the cumulative JSON payload-byte maximum.
    #[cfg(feature = "json")]
    pub fn max_json_payload_bytes(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_payload_bytes(maximum).build();
        self
    }

    /// Builds immutable limits.
    #[must_use]
    pub fn build(self) -> RedactionLimits {
        RedactionLimits {
            max_input_bytes: self.max_input_bytes,
            max_output_bytes: self.max_output_bytes,
            domain: self.domain,
            #[cfg(feature = "json")]
            json: self.json,
        }
    }
}

impl Default for RedactionLimitsBuilder {
    /// Returns conservative finite defaults for every mutable limit.
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_output_bytes: 16 * 1024,
            domain: StructureLimits::builder()
                .max_depth(32)
                .max_nodes(1_024)
                .max_sequence_items(256)
                .max_map_entries(256)
                .max_key_bytes(256)
                .build(),
            #[cfg(feature = "json")]
            json: JsonValueLimits::default(),
        }
    }
}

impl Default for RedactionLimits {
    /// Builds the immutable standard limit snapshot.
    fn default() -> Self {
        Self::builder().build()
    }
}
