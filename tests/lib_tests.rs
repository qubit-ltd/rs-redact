// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for crate-level exports.

use qubit_redact::RedactedDebug;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::argv::ArgvRedactor;
use qubit_redact::env::EnvRedactor;
use qubit_redact::redacted_debug;
/// Verifies the intended top-level redaction types remain publicly exported.
#[test]
fn test_lib_exports_public_api() {
    let policy = RedactionPolicy::default();
    let redactor = Redactor::new(policy);
    let _ = ArgvRedactor::new(redactor.clone());
    let _ = EnvRedactor::new(redactor);
    let _: RedactedDebug<'_, str> = redacted_debug("secret");
}
