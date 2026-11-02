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

    /// Sets the maximum UTF-8 byte length of domain fields and supported
    /// non-JSON format classification keys, after format-required decoding
    /// and before policy normalization or value access. JSON object keys use
    /// the independent `max_json_key_bytes` limit. Set both methods
    /// when both key scopes need bounds. This does not limit argv heuristics.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum UTF-8 key bytes in the shared non-JSON scope. Zero
    ///   is permitted.
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

    /// Sets the maximum UTF-8 byte length of a decoded JSON object key.
    /// This is independent of [`Self::max_key_bytes`]; configuring a general
    /// key limit does not constrain JSON keys.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum decoded JSON object-key UTF-8 bytes. Zero is
    ///   permitted.
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

#[cfg(all(test, feature = "serde", feature = "json"))]
mod tests {
    use super::RedactionLimits;

    #[test]
    fn test_builder_settings_and_snapshot_accessors() {
        let mut builder = RedactionLimits::builder();
        builder
            .max_input_bytes(101)
            .max_output_bytes(102)
            .max_serde_payload_bytes(103)
            .max_depth(4)
            .max_nodes(105)
            .max_collection_items(6)
            .max_key_bytes(107)
            .max_json_depth(8)
            .max_json_nodes(109)
            .max_json_collection_items(10)
            .max_json_key_bytes(111)
            .max_json_string_bytes(112)
            .max_json_number_bytes(113)
            .max_json_payload_bytes(114);

        let limits = builder.build();
        assert_eq!(limits.max_input_bytes(), 101);
        assert_eq!(limits.max_output_bytes(), 102);
        assert_eq!(limits.max_serde_payload_bytes(), 103);
        assert_eq!(limits.max_depth(), Some(4));
        assert_eq!(limits.max_nodes(), Some(105));
        assert_eq!(limits.max_collection_items(), Some(6));
        assert_eq!(limits.max_key_bytes(), Some(107));
        assert_eq!(limits.max_json_depth(), Some(8));
        assert_eq!(limits.max_json_nodes(), Some(109));
        assert_eq!(limits.max_json_collection_items(), Some(10));
        assert_eq!(limits.max_json_key_bytes(), Some(111));
        assert_eq!(limits.max_json_string_bytes(), Some(112));
        assert_eq!(limits.max_json_number_bytes(), Some(113));
        assert_eq!(limits.max_json_payload_bytes(), Some(114));
    }
}
