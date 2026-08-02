// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Isolated global-configuration test for derived map redaction.

use std::collections::BTreeMap;

use qubit_redact::{
    GlobalRedactionConfig,
    Redact,
    RedactionPolicy,
    Sensitivity,
};
use qubit_redact_derive::Redact;

/// Event whose map uses the process-wide redaction configuration.
#[derive(Redact)]
struct Event {
    /// Runtime-keyed metadata.
    #[redact(map)]
    metadata: BTreeMap<String, String>,
}

/// Verifies parameterless views snapshot the installed global configuration.
#[test]
fn test_map_uses_global_redaction_config() {
    let policy = RedactionPolicy::builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .build()
        .expect("the field rule is valid");
    GlobalRedactionConfig::from_policy(policy)
        .install()
        .expect("this test process installs the global configuration once");
    let event = Event {
        metadata: BTreeMap::from([(
            "tenant_secret".to_owned(),
            "raw-global-secret".to_owned(),
        )]),
    };

    let rendered = format!("{:?}", event.redacted());

    assert!(!rendered.contains("raw-global-secret"));
    assert_eq!(event.metadata["tenant_secret"], "raw-global-secret");
}
