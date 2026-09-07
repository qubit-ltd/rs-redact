// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished domain item summaries retain their structural provenance.

use crate::Redact;
use crate::RedactionWriter;
use crate::Redactor;

/// Individually resolved domain values must retain the structural reason
/// too; their per-item summary is derived from the same writer state.
#[cfg(feature = "json")]
#[test]
fn test_writer_json_handle_preserves_shared_structure_reason() {
    let policy = crate::RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(1);
        })
        .expect("the limit draft should build")
        .build()
        .expect("the policy should build");
    let mut batch = Redactor::new(policy).diagnostic_batch();
    let handle = batch.redact_value(&JsonContainerWithValidNestedValue);
    let output = batch.finish();
    let item = output.resolve(handle).expect("the handle should resolve");

    assert!(
        item.summary()
            .reasons()
            .contains(crate::RedactionReason::DepthLimitReached)
    );
    assert!(
        !item
            .summary()
            .reasons()
            .contains(crate::RedactionReason::OutputLimitReached)
    );
}

#[cfg(feature = "json")]
struct JsonContainerWithValidNestedValue;

#[cfg(feature = "json")]
impl Redact for JsonContainerWithValidNestedValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("JsonContainer", |fields| {
            fields.json("payload", r#"{"outer":{"inner":"value"}}"#);
        });
    }
}
