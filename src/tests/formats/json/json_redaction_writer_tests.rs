// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parser-entry accounting unavailable through the public API.

use crate::Redactor;
use crate::formats::json::parse_counter::json_parse_count;
use crate::formats::json::parse_counter::reset_json_parse_count;

#[test]
fn test_enabled_json_text_is_parsed_exactly_once() {
    reset_json_parse_count();

    let output = Redactor::standard().redact_json(r#"{"token":"raw-secret"}"#);

    assert_eq!(json_parse_count(), 1);
    assert!(!output.text().as_str().contains("raw-secret"));
}
