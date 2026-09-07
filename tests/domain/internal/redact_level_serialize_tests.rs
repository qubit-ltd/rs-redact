// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public decimal adapters share the structured input budget.

use bigdecimal::BigDecimal;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::domain::internal::RedactSerializeScope;
use qubit_redact::domain::internal::RedactedLevelSerializeRef;

/// Verifies decimal leaves use the same cumulative bounded formatter as
/// primitive structured values.
#[test]
fn test_big_decimal_level_values_share_the_input_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(4);
        })
        .expect("limits")
        .build()
        .expect("redaction policy");
    let values = vec![
        "123".parse::<BigDecimal>().expect("first decimal"),
        "45".parse::<BigDecimal>().expect("second decimal"),
    ];
    let _scope = RedactSerializeScope::new(&policy);

    let encoded = serde_json::to_value(RedactedLevelSerializeRef::new(&values, &policy, Sensitivity::Low))
        .expect("structured decimal serialization");

    assert_eq!(encoded[1], "<redacted>");
}
