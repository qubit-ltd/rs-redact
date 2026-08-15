// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI component mask encoding through the public redactor.

use qubit_redact::MaskPolicy;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::uri::UriRedactor;
/// Verifies Unicode, controls, and URI delimiters are percent encoded.
#[test]
fn test_uri_component_writer_encodes_mask_fragments() {
    let core = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().disable_floor();
        builder
            .fields()
            .raise("password", Sensitivity::Secret)
            .expect("the password rule is valid");
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("密\n/?#%"))
            .expect("the mask is valid");
        builder
    })
    .build()
    .expect("the policy is valid");
    let policy = RedactionPolicy::builder_from(&core)
        .build()
        .expect("the URI policy is valid");
    let result = UriRedactor::new(policy)
        .redact_uri_str("https://example.test/?password=secret");

    assert_eq!(
        result.log_safe_text().as_str(),
        "https://example.test/?password=%E5%AF%86%0A%2F%3F%23%25",
    );
}
