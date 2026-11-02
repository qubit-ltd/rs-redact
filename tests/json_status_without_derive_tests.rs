// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "json")]

use qubit_redact::Redactor;
use qubit_redact::domain::internal::RedactSerializeSource;
use serde::Serialize;

struct PlainValue {
    count: u32,
}

#[derive(Serialize)]
struct PlainProjection<'value> {
    count: &'value u32,
}

impl RedactSerializeSource for PlainValue {
    type RedactedFields<'value> = PlainProjection<'value>;

    fn redacted_fields<'value>(&'value self, _: &qubit_redact::RedactionPolicy) -> Self::RedactedFields<'value> {
        PlainProjection { count: &self.count }
    }
}

#[test]
fn test_json_status_api_does_not_require_derive_feature() {
    let output = Redactor::standard()
        .to_json_with_status(&PlainValue { count: 7 })
        .unwrap();

    assert!(output.is_complete());
    assert_eq!(output.json(), r#"{"count":7}"#);
}
