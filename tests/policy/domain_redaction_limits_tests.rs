// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for domain-structure redaction limits.

use qubit_redact::RedactionPolicy;
use qubit_redact::policy::DomainRedactionLimits;
use qubit_redact::policy::DomainRedactionLimitsError;

/// Verifies the fixed defaults bound every domain-structure dimension.
#[test]
fn test_domain_limits_have_fixed_safe_defaults() {
    let limits = DomainRedactionLimits::default();

    assert_eq!(limits.max_nodes(), 1024);
    assert_eq!(limits.max_collection_items(), 256);
    assert_eq!(limits.max_depth(), 32);
}

/// Verifies each zero dimension reports its specific validation error.
#[test]
fn test_domain_limits_reject_each_zero_dimension() {
    assert_eq!(
        DomainRedactionLimits::builder()
            .max_nodes(0)
            .max_collection_items(1)
            .max_depth(1)
            .build(),
        Err(DomainRedactionLimitsError::ZeroMaxNodes),
    );
    assert_eq!(
        DomainRedactionLimits::builder()
            .max_nodes(1)
            .max_collection_items(0)
            .max_depth(1)
            .build(),
        Err(DomainRedactionLimitsError::ZeroMaxCollectionItems),
    );
    assert_eq!(
        DomainRedactionLimits::builder()
            .max_nodes(1)
            .max_collection_items(1)
            .max_depth(0)
            .build(),
        Err(DomainRedactionLimitsError::ZeroMaxDepth),
    );
}

/// Verifies the grouped limits builder preserves domain limits in policies and
/// copied builders.
#[test]
fn test_domain_limits_builder_preserves_configured_limits() {
    let limits = DomainRedactionLimits::builder()
        .max_nodes(8)
        .max_collection_items(4)
        .max_depth(2)
        .build()
        .expect("the test domain limits should be valid");
    let mut builder = RedactionPolicy::builder();
    builder.limits().domain(limits);
    let policy = builder
        .build()
        .expect("the policy should preserve valid domain limits");

    assert_eq!(policy.limits().domain(), limits);
    assert_eq!(
        RedactionPolicy::builder_from(&policy)
            .build()
            .expect("the copied policy should build")
            .limits()
            .domain(),
        limits,
    );
}
