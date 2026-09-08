// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mandatory URI boundary protection under application policy overrides.

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Sensitivity;
use qubit_redact::formats::uri::UriRedactionBoundary;

/// Adding the mandatory boundary floor retains an application floor.
#[test]
fn test_boundary_adds_standard_floor_without_replacing_application_floor() {
    let provider_floor = RedactionFloor::builder()
        .raise("provider_ticket", Sensitivity::Secret)
        .expect("valid floor field")
        .build()
        .expect("valid floor");
    let application = RedactionPolicy::builder()
        .fields(|fields| {
            fields.disable_floor();
            fields.floor(provider_floor);
        })
        .expect("valid fields")
        .build()
        .expect("valid policy");
    let boundary = UriRedactionBoundary::new(&application);
    assert!(boundary.policy().sensitivity_for("provider_ticket").is_some());
    assert!(
        boundary
            .inspect_uri("https://example.test/?provider_ticket=raw")
            .expect("valid URI")
            .contains_sensitive()
    );
}

/// A disabled application snapshot cannot disable the boundary's standard
/// floor.
#[test]
fn test_boundary_protects_sensitive_uri_when_application_redaction_is_disabled() {
    let application = RedactionPolicy::disabled();
    let boundary = UriRedactionBoundary::new(&application);
    let uri = "https://example.test/?password=raw-secret&name=ada";

    let output = boundary.redact_uri(uri);

    assert!(application.is_disabled());
    assert!(!boundary.policy().is_disabled());
    assert!(!output.summary().is_redaction_disabled());
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(!output.text().as_str().contains("raw-secret"));
    assert!(output.text().as_str().contains("name=ada"));
    assert!(boundary.inspect_uri(uri).expect("valid URI").contains_sensitive());
    assert!(
        !boundary
            .inspect_uri("https://example.test/?name=ada")
            .expect("valid public URI")
            .contains_sensitive()
    );
}

/// Mandatory confidentiality retains caller resource limits and malformed-input
/// errors.
#[test]
fn test_boundary_retains_input_limits_and_inconclusive_inspection() {
    let application = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_input_bytes(8);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let boundary = UriRedactionBoundary::new(&application);
    let uri = "https://example.test/?password=raw-secret";

    let output = boundary.redact_uri(uri);

    assert!(!output.text().as_str().contains("raw-secret"));
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(boundary.inspect_uri(uri).is_err());
    let boundary = UriRedactionBoundary::new(&RedactionPolicy::disabled());
    assert!(boundary.inspect_uri("https://example.test/?password=%zz").is_err());
}
