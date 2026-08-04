// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for bounded URI output.

use qubit_redact::{
    InputOutputLimit,
    RedactionPolicy,
    UriRedactor,
};

/// Verifies URI output remains UTF-8 and reserves the complete marker.
#[test]
fn test_bounded_uri_output_keeps_utf8_and_marker_complete() {
    let budget = InputOutputLimit::new(4096, 37)
        .expect("the output can contain the marker");
    let core = RedactionPolicy::default()
        .to_builder()
        .diagnostic_event(budget)
        .build()
        .expect("the core policy is valid");
    let policy = RedactionPolicy::builder_from(&core)
        .build()
        .expect("the URI policy is valid");
    let input = format!("https://example.test/{}", "%E4%BD%A0".repeat(32));
    let result = UriRedactor::new(policy).redact_uri_str(&input);

    assert!(
        result.log_safe_text().as_str().ends_with("<truncated>"),
        "{}",
        result.log_safe_text().as_str()
    );
    assert!(result.log_safe_text().as_str().len() <= 37);
    let payload = result
        .log_safe_text()
        .as_str()
        .strip_suffix("<truncated>")
        .expect("the result has a truncation marker");
    assert!(!payload.ends_with('%'));
    assert!(!payload.ends_with("%E"));
    assert!(
        std::str::from_utf8(result.log_safe_text().as_ref().as_bytes()).is_ok()
    );
}

/// Verifies percent-encoded replacement bytes are emitted as complete pieces.
#[test]
fn test_bounded_uri_output_percent_encodes_unicode_masks() {
    let core = RedactionPolicy::default()
        .to_builder()
        .mask(
            qubit_redact::Sensitivity::High,
            qubit_redact::MaskPolicy::fixed("密"),
        )
        .expect("the mask policy is valid")
        .build()
        .expect("the core policy is valid");
    let policy = RedactionPolicy::builder_from(&core)
        .build()
        .expect("the URI policy is valid");
    let result = UriRedactor::new(policy)
        .redact_uri_str("https://example.test/?password=secret#fragment");

    assert!(result.log_safe_text().as_str().contains("%E5%AF%86"));
    assert!(!result.log_safe_text().as_str().contains("secret"));
}
