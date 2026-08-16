// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable limits for bounded domain-object traversal.
// qubit-style: allow multiple-public-types

use super::DomainRedactionLimitsError;

/// Mutable construction state for [`DomainRedactionLimits`].
#[derive(Debug, Clone, Copy)]
pub struct DomainRedactionLimitsBuilder {
    max_nodes: usize,
    max_collection_items: usize,
    max_depth: usize,
}

/// Bounds cumulative domain nodes, collection items, and active nesting depth.
///
/// A root domain value consumes one node at depth one. Each field admitted for
/// access consumes another node, while each collection element admitted before
/// iterator advancement consumes one collection item. Node and collection-item
/// charges accumulate for the lifetime of one redaction session; active depth
/// is restored when a domain-value scope is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainRedactionLimits {
    max_nodes: usize,
    max_collection_items: usize,
    max_depth: usize,
}

impl DomainRedactionLimits {
    /// Default cumulative number of domain values and fields admitted.
    pub const DEFAULT_MAX_NODES: usize = 1024;
    /// Default cumulative number of collection elements admitted.
    pub const DEFAULT_MAX_COLLECTION_ITEMS: usize = 256;
    /// Default maximum active domain-value depth, with the root at depth one.
    pub const DEFAULT_MAX_DEPTH: usize = 32;

    /// Creates a builder initialized with the standard domain limits.
    #[must_use]
    #[inline]
    pub const fn builder() -> DomainRedactionLimitsBuilder {
        DomainRedactionLimitsBuilder {
            max_nodes: Self::DEFAULT_MAX_NODES,
            max_collection_items: Self::DEFAULT_MAX_COLLECTION_ITEMS,
            max_depth: Self::DEFAULT_MAX_DEPTH,
        }
    }

    /// Creates validated domain-structure limits.
    ///
    /// `max_nodes` bounds cumulative domain-value and field admissions,
    /// `max_collection_items` bounds admissions performed before advancing
    /// collection iterators, and `max_depth` bounds simultaneously active
    /// domain-value scopes with the root at depth one.
    ///
    /// # Errors
    ///
    /// Returns the corresponding [`DomainRedactionLimitsError`] variant when
    /// any argument is zero. Dimensions are checked in parameter order.
    #[inline]
    const fn from_builder(
        max_nodes: usize,
        max_collection_items: usize,
        max_depth: usize,
    ) -> Result<Self, DomainRedactionLimitsError> {
        if max_nodes == 0 {
            return Err(DomainRedactionLimitsError::ZeroMaxNodes);
        }
        if max_collection_items == 0 {
            return Err(DomainRedactionLimitsError::ZeroMaxCollectionItems);
        }
        if max_depth == 0 {
            return Err(DomainRedactionLimitsError::ZeroMaxDepth);
        }
        Ok(Self {
            max_nodes,
            max_collection_items,
            max_depth,
        })
    }

    /// Returns the cumulative domain-value and field admission limit.
    #[inline(always)]
    pub const fn max_nodes(&self) -> usize {
        self.max_nodes
    }

    /// Returns the cumulative collection-element admission limit.
    #[inline(always)]
    pub const fn max_collection_items(&self) -> usize {
        self.max_collection_items
    }

    /// Returns the active domain-value depth limit.
    #[inline(always)]
    #[must_use]
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }
}

impl DomainRedactionLimitsBuilder {
    /// Sets the cumulative domain-value and field admission limit.
    #[inline]
    pub const fn max_nodes(mut self, max_nodes: usize) -> Self {
        self.max_nodes = max_nodes;
        self
    }

    /// Sets the cumulative collection-element admission limit.
    #[inline]
    pub const fn max_collection_items(
        mut self,
        max_collection_items: usize,
    ) -> Self {
        self.max_collection_items = max_collection_items;
        self
    }

    /// Sets the active domain-value depth limit.
    #[inline]
    pub const fn max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Builds validated domain-structure limits.
    #[inline]
    pub const fn build(
        self,
    ) -> Result<DomainRedactionLimits, DomainRedactionLimitsError> {
        DomainRedactionLimits::from_builder(
            self.max_nodes,
            self.max_collection_items,
            self.max_depth,
        )
    }
}

impl Default for DomainRedactionLimits {
    /// Returns the fixed safe defaults of 1024 nodes, 256 collection items,
    /// and an active depth of 32.
    #[inline(always)]
    fn default() -> Self {
        Self::builder()
            .build()
            .expect("default domain limits are valid")
    }
}
