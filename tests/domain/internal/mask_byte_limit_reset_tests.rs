// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for restoring bounded-mask state after formatting exits abnormally.

use std::{
    collections::BTreeMap,
    fmt,
    panic::AssertUnwindSafe,
};

use qubit_redact::{
    LogOutputLimit,
    MaskPolicy,
    Redact,
    RedactedMap,
    RedactionPolicy,
    Sensitivity,
};

/// Redacted value that aborts formatting after bounded state has been entered.
struct PanickingRedact;

impl Redact for PanickingRedact {
    /// Panics to exercise scope-guard restoration during redacted formatting.
    fn fmt_redacted(
        &self,
        _policy: &RedactionPolicy,
        _formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        panic!("intentional formatting panic")
    }
}

/// Verifies a formatting panic cannot retain a stale bounded-mask ceiling.
#[test]
fn test_mask_byte_limit_reset_restores_unbounded_state_after_panic() {
    let limit = LogOutputLimit::new(14)
        .expect("the bounded rendering limit should be valid");
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = PanickingRedact
            .redacted()
            .with_output_limit(limit)
            .to_string();
    }));
    assert!(result.is_err());

    let policy = RedactionPolicy::builder()
        .disable_floor()
        .raise("password", Sensitivity::Low)
        .expect("the test builder input should be valid")
        .mask(Sensitivity::Low, MaskPolicy::preserve_suffix(16, "****", 0))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the masking policy should be valid");
    let values = BTreeMap::from([("password", "abcdefghijklmnopqrstuvwxyz")]);

    let output = RedactedMap::new(&values, policy).to_string();

    assert!(output.contains("****klmnopqrstuvwxyz"), "{output}");
    assert!(!output.contains("abcdefghijklmnopqrstuvwxyz"), "{output}");
}
