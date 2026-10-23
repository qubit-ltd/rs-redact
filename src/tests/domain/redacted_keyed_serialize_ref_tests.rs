// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal contract tests for the keyed Serde adapter.

use crate::RedactionPolicy;
use crate::domain::internal::RedactedKeyedSerializeRef;

/// Verifies structured Serde classifies keyed values through the active policy.
#[test]
fn test_redacted_keyed_serialize_ref_classifies_by_policy_key() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("password");
        })
        .expect("field policy should build")
        .build()
        .expect("policy should build");

    let secret = Some("raw-secret".to_owned());
    let public = Some("eu-west".to_owned());
    let secret_json = serde_json::to_value(RedactedKeyedSerializeRef::new(&secret, "password", &policy))
        .expect("secret keyed value should serialize");
    let public_json = serde_json::to_value(RedactedKeyedSerializeRef::new(&public, "region", &policy))
        .expect("public keyed value should serialize");

    assert_eq!(secret_json, serde_json::json!("<redacted>"));
    assert_eq!(public_json, serde_json::json!("eu-west"));
}
