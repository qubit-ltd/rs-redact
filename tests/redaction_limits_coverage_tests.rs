// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Complete public accessor coverage for redaction limits.

use qubit_redact::RedactionLimits;

/// Verifies every domain and JSON builder setting survives the immutable
/// snapshot boundary.
#[cfg(feature = "json")]
#[test]
fn test_redaction_limits_builder_round_trips_every_public_limit() {
    let mut builder = RedactionLimits::builder();
    builder
        .max_input_bytes(101)
        .max_output_bytes(102)
        .max_depth(3)
        .max_nodes(104)
        .max_collection_items(5)
        .max_key_bytes(106)
        .max_json_depth(7)
        .max_json_nodes(108)
        .max_json_collection_items(9)
        .max_json_key_bytes(110)
        .max_json_string_bytes(111)
        .max_json_number_bytes(112)
        .max_json_payload_bytes(113);
    let limits = builder.build();

    assert_eq!(limits.max_input_bytes(), 101);
    assert_eq!(limits.max_output_bytes(), 102);
    assert_eq!(limits.max_depth(), Some(3));
    assert_eq!(limits.max_nodes(), Some(104));
    assert_eq!(limits.max_collection_items(), Some(5));
    assert_eq!(limits.max_key_bytes(), Some(106));
    assert_eq!(limits.max_json_depth(), Some(7));
    assert_eq!(limits.max_json_nodes(), Some(108));
    assert_eq!(limits.max_json_collection_items(), Some(9));
    assert_eq!(limits.max_json_key_bytes(), Some(110));
    assert_eq!(limits.max_json_string_bytes(), Some(111));
    assert_eq!(limits.max_json_number_bytes(), Some(112));
    assert_eq!(limits.max_json_payload_bytes(), Some(113));
}

/// Verifies the default snapshot is identical to the default builder output.
#[test]
fn test_redaction_limits_default_matches_default_builder() {
    assert_eq!(RedactionLimits::default(), RedactionLimits::builder().build());
}
