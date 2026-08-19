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
    max_input_bytes: usize,
    max_output_bytes: usize,
    domain: StructureLimits,
    #[cfg(feature = "json")]
    json: JsonValueLimits,
}

/// Structural and JSON limits for one redaction operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionLimits {
    max_input_bytes: usize,
    max_output_bytes: usize,
    domain: StructureLimits,
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

    /// Returns the structural limits used by domain traversal.
    #[must_use]
    pub const fn domain(&self) -> StructureLimits {
        self.domain
    }

    /// Returns the maximum source bytes one transaction may inspect.
    #[must_use]
    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    /// Returns the maximum safe output bytes one transaction may retain.
    #[must_use]
    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    /// Returns the JSON value limits used by JSON traversal.
    #[cfg(feature = "json")]
    #[must_use]
    pub const fn json(&self) -> JsonValueLimits {
        self.json
    }

    /// Returns the JSON point limits with structural dimensions removed.
    /// A redaction transaction owns depth, node, and collection admission in
    /// its one shared structural ledger; JSON traversal retains only its
    /// format-specific scalar and payload limits.
    #[cfg(feature = "json")]
    #[must_use]
    pub(crate) fn json_point_limits(&self) -> JsonValueLimits {
        Self::json_point_limits_from(self.json)
    }

    /// Removes JSON-local structural limits while retaining JSON-specific
    /// point limits. This is used by nested HTTP JSON rendering as well.
    #[cfg(feature = "json")]
    #[must_use]
    pub(crate) fn json_point_limits_from(limits: JsonValueLimits) -> JsonValueLimits {
        let mut builder = JsonValueLimits::builder().structure_limits(StructureLimits::new());
        if let Some(limit) = limits.string_bytes_limit() {
            builder = builder.string_bytes_limit(*limit);
        }
        if let Some(limit) = limits.number_bytes_limit() {
            builder = builder.number_bytes_limit(*limit);
        }
        if let Some(limit) = limits.payload_bytes_limit() {
            builder = builder.payload_bytes_limit(*limit);
        }
        builder.build()
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
    /// Sets the structural limits used by domain traversal.
    pub fn domain(&mut self, limits: StructureLimits) -> &mut Self {
        self.domain = limits;
        self
    }

    /// Sets the JSON value limits.
    #[cfg(feature = "json")]
    pub fn json(&mut self, limits: JsonValueLimits) -> &mut Self {
        self.json = limits;
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
    fn default() -> Self {
        Self::builder().build()
    }
}
