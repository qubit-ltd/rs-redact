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
    domain: StructureLimits,
    #[cfg(feature = "json")]
    json: JsonValueLimits,
}

/// Structural and JSON limits for one redaction operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionLimits {
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

    /// Returns the JSON value limits used by JSON traversal.
    #[cfg(feature = "json")]
    #[must_use]
    pub const fn json(&self) -> JsonValueLimits {
        self.json
    }
}

impl RedactionLimitsBuilder {
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
            domain: self.domain,
            #[cfg(feature = "json")]
            json: self.json,
        }
    }
}

impl Default for RedactionLimitsBuilder {
    fn default() -> Self {
        Self {
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
