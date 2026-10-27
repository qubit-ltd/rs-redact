// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Read-only structural validation before a JSON value tree is materialized.

use qubit_budget::json::JsonDecodeLimits;
use qubit_budget::json::JsonResource;
use qubit_budget::json::JsonValueLimits;
use qubit_json::decode::JsonDecoder;

/// Snapshot of shared structural capacity for one JSON text value.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JsonStructurePreflight {
    pub(crate) remaining_nodes: Option<usize>,
    pub(crate) remaining_items: Option<usize>,
    pub(crate) max_relative_depth: Option<usize>,
    pub(crate) traversal_closed: bool,
}

/// Value-free failure from shared JSON structural validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonStructurePreflightError {
    Invalid,
    DepthLimit,
    TraversalLimit,
}

impl JsonStructurePreflight {
    /// Validates syntax and shared structural ceilings without constructing a
    /// tree.
    pub(crate) fn validate(&self, text: &str) -> Result<(), JsonStructurePreflightError> {
        if self.traversal_closed {
            return Err(JsonStructurePreflightError::TraversalLimit);
        }
        let node_limit = node_cap(self.remaining_nodes, self.remaining_items);
        if node_limit.is_none() && self.max_relative_depth.is_none() {
            return Ok(());
        }
        let mut values = JsonValueLimits::new().into_builder();
        if let Some(nodes) = node_limit {
            values = values.max_nodes(nodes);
        }
        if let Some(depth) = self.max_relative_depth {
            values = values.max_depth(depth);
        }
        let limits = JsonDecodeLimits::builder().value_limits(values.build()).build();
        let mut decoder = JsonDecoder::with_limits(limits);
        decoder
            .validate_str(text)
            .map_err(|error| match error.budget_error().map(|budget| budget.resource()) {
                Some(JsonResource::Depth) => JsonStructurePreflightError::DepthLimit,
                Some(JsonResource::Nodes | JsonResource::SequenceItems | JsonResource::MapEntries) => {
                    JsonStructurePreflightError::TraversalLimit
                }
                Some(_) => JsonStructurePreflightError::TraversalLimit,
                None => JsonStructurePreflightError::Invalid,
            })
    }
}

fn min_optional(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn node_cap(nodes: Option<usize>, items: Option<usize>) -> Option<usize> {
    min_optional(nodes, items.and_then(|items| items.checked_add(1)))
}

#[cfg(test)]
mod tests {
    use super::JsonStructurePreflight;
    use super::JsonStructurePreflightError;
    use super::min_optional;
    use super::node_cap;

    #[test]
    fn test_node_cap_handles_unlimited_zero_and_overflow_boundaries() {
        assert_eq!(min_optional(None, None), None);
        assert_eq!(node_cap(None, None), None);
        assert_eq!(node_cap(Some(0), None), Some(0));
        assert_eq!(node_cap(None, Some(0)), Some(1));
        assert_eq!(node_cap(Some(9), Some(3)), Some(4));
        assert_eq!(node_cap(Some(usize::MAX), Some(usize::MAX)), Some(usize::MAX));
    }

    #[test]
    fn test_snapshot_validates_root_and_relative_depth_limits() {
        let snapshot = JsonStructurePreflight {
            remaining_nodes: Some(1),
            remaining_items: Some(0),
            max_relative_depth: None,
            traversal_closed: false,
        };
        assert!(snapshot.validate("0").is_ok());
        assert!(snapshot.validate("[]").is_ok());
        assert_eq!(
            snapshot.validate("[0]"),
            Err(JsonStructurePreflightError::TraversalLimit)
        );

        let depth_limited = JsonStructurePreflight {
            remaining_nodes: None,
            remaining_items: None,
            max_relative_depth: Some(1),
            traversal_closed: false,
        };
        assert_eq!(
            depth_limited.validate("[[]]"),
            Err(JsonStructurePreflightError::DepthLimit)
        );
    }

    #[test]
    fn test_closed_traversal_rejects_before_validation() {
        let snapshot = JsonStructurePreflight {
            remaining_nodes: None,
            remaining_items: None,
            max_relative_depth: None,
            traversal_closed: true,
        };
        assert_eq!(
            snapshot.validate("not json"),
            Err(JsonStructurePreflightError::TraversalLimit)
        );
    }
}
