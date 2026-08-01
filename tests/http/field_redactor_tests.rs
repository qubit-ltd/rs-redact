// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for borrowed HTTP field-rule execution.

use http::{
    HeaderMap,
    HeaderValue,
};
use qubit_redact::{
    MaskPolicy,
    RedactionFloor,
    RedactionPolicy,
    Sensitivity,
    http::{
        HttpRedactionPolicy,
        HttpRedactor,
    },
};

/// Verifies header field execution uses the floor-selected mask atomically.
#[test]
fn test_field_redactor_uses_floor_mask_for_header_rule() {
    let floor = RedactionFloor::empty_builder()
        .raise("tenant_token", Sensitivity::Low)
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[floor-secret]"))
        .build()
        .expect("the floor should be valid");
    let application = RedactionPolicy::empty_builder()
        .disable_floor()
        .raise("tenant_token", Sensitivity::Secret)
        .mask(
            Sensitivity::Secret,
            MaskPolicy::fixed("[application-secret]"),
        )
        .build()
        .expect("the application policy should be valid");
    let policy = HttpRedactionPolicy::empty_builder()
        .header_rules(application.rules().clone().with_floor(floor))
        .build()
        .expect("the HTTP policy should be valid");
    let mut headers = HeaderMap::new();
    headers.insert("tenant-token", HeaderValue::from_static("source-secret"));

    let rendered = HttpRedactor::new(policy)
        .redact_headers(&headers)
        .to_string();

    assert!(rendered.contains("[floor-secret]"));
    assert!(!rendered.contains("source-secret"));
    assert!(!rendered.contains("[application-secret]"));
}
