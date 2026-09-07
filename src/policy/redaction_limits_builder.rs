// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable construction of redaction resource ceilings.

use qubit_budget::StructureLimits;
#[cfg(feature = "json")]
use qubit_budget::json::JsonValueLimits;

use super::RedactionLimits;

/// Mutable construction state for [`RedactionLimits`].
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionLimits;
///
/// let mut builder = RedactionLimits::builder();
/// builder.max_input_bytes(256).max_output_bytes(64);
/// let limits = builder.build();
/// assert_eq!(limits.max_input_bytes(), 256);
/// assert_eq!(limits.max_output_bytes(), 64);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RedactionLimitsBuilder {
    /// Draft maximum source bytes admitted for inspection.
    max_input_bytes: usize,
    /// Draft maximum safe bytes retained in output.
    max_output_bytes: usize,
    /// Maximum logical scalar bytes passed to a Serde serializer.
    #[cfg(feature = "serde")]
    max_serde_payload_bytes: usize,
    /// Draft structural limits shared by domain and format traversal.
    domain: StructureLimits,
    /// Draft JSON-specific structural and payload limits.
    #[cfg(feature = "json")]
    json: JsonValueLimits,
}

impl RedactionLimitsBuilder {
    /// Copies an immutable snapshot into mutable construction state.
    ///
    /// # Parameters
    ///
    /// - `base`: Snapshot whose ceilings initialize the builder.
    ///
    /// # Returns
    ///
    /// A builder whose initial output equals the supplied snapshot.
    #[must_use]
    #[inline(always)]
    pub(super) fn from_limits(base: &RedactionLimits) -> Self {
        Self {
            max_input_bytes: base.max_input_bytes(),
            max_output_bytes: base.max_output_bytes(),
            #[cfg(feature = "serde")]
            max_serde_payload_bytes: base.max_serde_payload_bytes(),
            domain: base.structural_limits(),
            #[cfg(feature = "json")]
            json: base.json_limits(),
        }
    }

    /// Sets the maximum source bytes one transaction may inspect.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Cumulative source bytes admitted by one transaction. Zero
    ///   is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[inline(always)]
    pub fn max_input_bytes(&mut self, maximum: usize) -> &mut Self {
        self.max_input_bytes = maximum;
        self
    }

    /// Sets the maximum safe output bytes one transaction may retain.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum final output bytes retained by one transaction.
    ///   Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[inline(always)]
    pub fn max_output_bytes(&mut self, maximum: usize) -> &mut Self {
        self.max_output_bytes = maximum;
        self
    }

    /// Sets the logical Serde payload allowance independently of encoded
    /// output.
    ///
    /// Zero permits empty scalar payloads. Policy construction rejects values
    /// above `isize::MAX`; third-party serializer framing is not charged here.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Logical scalar bytes admitted by one structured Serde
    ///   scope. Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[cfg(feature = "serde")]
    #[inline(always)]
    pub fn max_serde_payload_bytes(&mut self, maximum: usize) -> &mut Self {
        self.max_serde_payload_bytes = maximum;
        self
    }

    /// Sets the maximum nested domain depth.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum active structural nesting depth. Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[inline(always)]
    pub fn max_depth(&mut self, maximum: usize) -> &mut Self {
        self.domain = self.domain.into_builder().max_depth(maximum).build();
        self
    }

    /// Sets the maximum admitted domain nodes.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum cumulative structural nodes. Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[inline(always)]
    pub fn max_nodes(&mut self, maximum: usize) -> &mut Self {
        self.domain = self.domain.into_builder().max_nodes(maximum).build();
        self
    }

    /// Sets the cumulative item allowance shared by transaction collections.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Cumulative sequence and map entries across transaction
    ///   collections. Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[inline(always)]
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
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum raw structural key bytes before classification.
    ///   Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[inline(always)]
    pub fn max_key_bytes(&mut self, maximum: usize) -> &mut Self {
        self.domain = self.domain.into_builder().max_key_bytes(maximum).build();
        self
    }

    /// Sets the maximum JSON nesting depth.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum JSON nesting depth. Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub fn max_json_depth(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_depth(maximum).build();
        self
    }

    /// Sets the maximum number of JSON nodes.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum JSON nodes. Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub fn max_json_nodes(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_nodes(maximum).build();
        self
    }

    /// Sets the maximum number of items in one JSON collection.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum entries in each JSON array or object. Zero is
    ///   permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[cfg(feature = "json")]
    #[inline(always)]
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
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum raw JSON object-key bytes. Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub fn max_json_key_bytes(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_key_bytes(maximum).build();
        self
    }

    /// Sets the maximum JSON string length.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum JSON string bytes. Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub fn max_json_string_bytes(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_string_bytes(maximum).build();
        self
    }

    /// Sets the maximum JSON number representation length.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum JSON number representation bytes. Zero is
    ///   permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub fn max_json_number_bytes(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_number_bytes(maximum).build();
        self
    }

    /// Sets the cumulative JSON payload-byte maximum.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Cumulative logical JSON payload bytes. Zero is permitted.
    ///
    /// # Returns
    ///
    /// This builder after replacing the selected ceiling.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub fn max_json_payload_bytes(&mut self, maximum: usize) -> &mut Self {
        self.json = self.json.into_builder().max_payload_bytes(maximum).build();
        self
    }

    /// Builds immutable limits.
    ///
    /// # Returns
    ///
    /// An immutable snapshot of all draft ceilings. Validation of addressable
    /// output and Serde payload sizes occurs when building the enclosing
    /// policy.
    #[must_use]
    #[inline(always)]
    pub fn build(self) -> RedactionLimits {
        RedactionLimits::from_parts(
            self.max_input_bytes,
            self.max_output_bytes,
            #[cfg(feature = "serde")]
            self.max_serde_payload_bytes,
            self.domain,
            #[cfg(feature = "json")]
            self.json,
        )
    }
}

impl Default for RedactionLimitsBuilder {
    /// Returns conservative finite defaults for every mutable limit.
    ///
    /// # Returns
    ///
    /// A builder with finite standard ceilings: 64 KiB input, 16 KiB output,
    /// 16 KiB Serde payload when enabled, and standard structural/JSON limits.
    #[inline(always)]
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_output_bytes: 16 * 1024,
            #[cfg(feature = "serde")]
            max_serde_payload_bytes: 16 * 1024,
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
