// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Crate-private JSON preflight capacity and rejection contracts.

use crate::runtime::JsonStructurePreflight;
use crate::runtime::JsonStructurePreflightError;

#[test]
fn test_snapshot_validates_root_and_relative_depth_limits() {
    let snapshot = JsonStructurePreflight {
        remaining_nodes: Some(1),
        remaining_items: Some(0),
        max_relative_depth: None,
        traversal_closed: false,
    };
    assert_eq!(snapshot.validate("0"), Ok(()), "a scalar fits one node");
    assert_eq!(snapshot.validate("[]"), Ok(()), "an empty array uses no items");
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
