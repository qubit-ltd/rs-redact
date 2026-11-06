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

pub(crate) use super::internal::json_structure_preflight_error::JsonStructurePreflightError;

/// Snapshot of shared structural capacity for one JSON text value.
///
/// `remaining_nodes` is the maximum number of value nodes available to this
/// text. `remaining_items` is converted to a node ceiling by adding the root
/// node with checked arithmetic, then taking the tighter configured ceiling.
/// `max_relative_depth` is the maximum value depth relative to the current
/// traversal. `traversal_closed` rejects validation before inspecting text.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JsonStructurePreflight {
    /// Value-node capacity remaining in the shared traversal.
    pub(crate) remaining_nodes: Option<usize>,
    /// Sequence-item and map-entry capacity remaining in the shared traversal.
    pub(crate) remaining_items: Option<usize>,
    /// Maximum nesting depth relative to the current traversal position.
    pub(crate) max_relative_depth: Option<usize>,
    /// Whether a previous traversal decision has closed further admission.
    pub(crate) traversal_closed: bool,
}

impl JsonStructurePreflight {
    /// Preflights JSON text against configured shared structural budgets.
    ///
    /// When no node/item or relative-depth ceiling is configured and traversal
    /// is open, validation is skipped and returns `Ok(())`; therefore success
    /// does not by itself guarantee valid JSON. Callers must still parse the
    /// text before using it as JSON. When a ceiling is configured, decoding
    /// checks syntax while enforcing that ceiling without materializing a value
    /// tree.
    ///
    /// # Parameters
    ///
    /// - `text`: JSON text to preflight.
    ///
    /// # Returns
    ///
    /// `Ok(())` when preflight is skipped or completed within the configured
    /// budgets.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` for malformed text, `DepthLimit` when the
    /// relative depth ceiling is exceeded, and `TraversalLimit` when traversal
    /// is closed or node/item capacity is exceeded.
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

/// Returns the tighter ceiling, treating an absent value as unlimited.
///
/// # Parameters
///
/// - `a`: First ceiling, or `None` for unlimited capacity.
/// - `b`: Second ceiling, or `None` for unlimited capacity.
///
/// # Returns
///
/// `Some` with the tighter configured ceiling, or `None` if both are unlimited.
#[must_use]
#[inline]
fn min_optional(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// Combines optional ceilings, where `None` means no limit.
///
/// # Parameters
///
/// - `nodes`: Available value nodes, or `None` for unlimited capacity.
/// - `items`: Available collection items, or `None` for unlimited capacity.
///
/// # Returns
///
/// `Some` with the tighter node ceiling after allowing for the root node, or
/// `None` if neither input imposes a representable bound. An overflowing
/// item-derived bound imposes no additional limit.
#[must_use]
#[inline]
fn node_cap(nodes: Option<usize>, items: Option<usize>) -> Option<usize> {
    // The root value is not a sequence item or map entry. Overflow means the
    // item-derived ceiling cannot add a tighter representable bound.
    min_optional(nodes, items.and_then(|items| items.checked_add(1)))
}

#[cfg(test)]
mod tests {
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
}
