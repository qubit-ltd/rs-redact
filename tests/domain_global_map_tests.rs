// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Isolated global-default test for derived map redaction.

use std::collections::BTreeMap;

use qubit_redact::{Redact, RedactionPolicy, Sensitivity};
use qubit_redact_derive::Redact;

/// Event whose map uses the process default policy.
#[derive(Redact)]
struct Event {
    /// Runtime-keyed metadata.
    #[redact(map)]
    metadata: BTreeMap<String, String>,
}

/// Verifies parameterless views snapshot the installed global default.
#[test]
fn test_map_uses_global_default_policy() {
    let policy = RedactionPolicy::builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .build()
        .expect("the field rule is valid");
    RedactionPolicy::set_global_default(policy).expect("this test process installs it once");
    let event = Event {
        metadata: BTreeMap::from([("tenant_secret".to_owned(), "raw-global-secret".to_owned())]),
    };

    let rendered = format!("{:?}", event.redacted());

    assert!(!rendered.contains("raw-global-secret"));
    assert_eq!(event.metadata["tenant_secret"], "raw-global-secret");
}
