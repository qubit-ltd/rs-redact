// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for session-scoped domain traversal accounting.

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::policy::DomainRedactionLimits;
use qubit_redact::policy::DomainTraversalAdmission;
use qubit_redact::policy::DomainValueAdmission;

/// Builds a redactor with the requested domain-structure limits.
fn redactor_with_domain_limits(
    max_nodes: usize,
    max_collection_items: usize,
    max_depth: usize,
) -> Redactor {
    let limits =
        DomainRedactionLimits::new(max_nodes, max_collection_items, max_depth)
            .expect("the test domain limits should be valid");
    let mut builder = RedactionPolicy::builder();
    builder.limits().domain(limits);
    let policy = builder
        .build()
        .expect("the policy should accept valid domain limits");
    Redactor::new(policy)
}

/// Verifies a nested depth rejection does not close sibling traversal and RAII
/// restores the active depth after the parent scope is dropped.
#[test]
fn test_domain_session_restores_depth_after_scope_drop() {
    let redactor = redactor_with_domain_limits(8, 8, 1);
    let mut session = redactor.session();
    let DomainValueAdmission::Entered(mut root) = session.enter_domain_value()
    else {
        panic!("the root value must be admitted");
    };

    assert!(matches!(
        root.session().enter_domain_value(),
        DomainValueAdmission::DepthLimitReached,
    ));
    drop(root);

    assert!(matches!(
        session.enter_domain_value(),
        DomainValueAdmission::Entered(_),
    ));
}

/// Verifies node charges are cumulative and exhaustion permanently closes
/// domain traversal for the session.
#[test]
fn test_domain_session_closes_traversal_when_nodes_are_exhausted() {
    let redactor = redactor_with_domain_limits(1, 8, 8);
    let mut session = redactor.session();
    let DomainValueAdmission::Entered(mut root) = session.enter_domain_value()
    else {
        panic!("the root value must consume the only node");
    };

    assert_eq!(root.admit_field(), DomainTraversalAdmission::LimitReached,);
    drop(root);

    assert!(matches!(
        session.enter_domain_value(),
        DomainValueAdmission::TraversalLimitReached,
    ));
}

/// Verifies dropping a scope restores depth without refunding nodes consumed
/// by that value and its fields.
#[test]
fn test_domain_session_does_not_refund_nodes_after_scope_drop() {
    let redactor = redactor_with_domain_limits(2, 8, 8);
    let mut session = redactor.session();
    let DomainValueAdmission::Entered(mut first) = session.enter_domain_value()
    else {
        panic!("the first value must be admitted");
    };

    assert_eq!(first.admit_field(), DomainTraversalAdmission::Render);
    drop(first);

    assert!(matches!(
        session.enter_domain_value(),
        DomainValueAdmission::TraversalLimitReached,
    ));
}

/// Verifies collection admission closes traversal before a caller would pull
/// another item from its iterator.
#[test]
fn test_domain_session_rejects_collection_item_before_iterator_advance() {
    let redactor = redactor_with_domain_limits(8, 1, 8);
    let mut session = redactor.session();
    let DomainValueAdmission::Entered(mut root) = session.enter_domain_value()
    else {
        panic!("the root value must be admitted");
    };
    let mut iterator_advances = 0;

    if root.admit_collection_item() == DomainTraversalAdmission::Render {
        iterator_advances += 1;
    }
    if root.admit_collection_item() == DomainTraversalAdmission::Render {
        iterator_advances += 1;
    }

    assert_eq!(iterator_advances, 1);
    drop(root);
    assert!(matches!(
        session.enter_domain_value(),
        DomainValueAdmission::TraversalLimitReached,
    ));
}

/// Verifies collection-item charges remain consumed after their owning scope
/// is dropped and a later scope is entered.
#[test]
fn test_domain_session_does_not_refund_collection_items_after_scope_drop() {
    let redactor = redactor_with_domain_limits(8, 1, 8);
    let mut session = redactor.session();
    let DomainValueAdmission::Entered(mut first) = session.enter_domain_value()
    else {
        panic!("the first value must be admitted");
    };

    assert_eq!(
        first.admit_collection_item(),
        DomainTraversalAdmission::Render,
    );
    drop(first);

    let DomainValueAdmission::Entered(mut second) =
        session.enter_domain_value()
    else {
        panic!("the later value must still have node and depth capacity");
    };
    assert_eq!(
        second.admit_collection_item(),
        DomainTraversalAdmission::LimitReached,
    );
}
