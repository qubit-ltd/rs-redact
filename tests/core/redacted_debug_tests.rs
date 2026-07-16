// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedDebug`](qubit_sanitize::RedactedDebug).

use qubit_sanitize::redacted_debug;

#[test]
fn test_redacted_debug_never_calls_inner_debug() {
    struct PanicDebug;

    impl std::fmt::Debug for PanicDebug {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("inner Debug must not be called");
        }
    }

    assert_eq!(format!("{:?}", redacted_debug(&PanicDebug)), "<redacted>");
}
