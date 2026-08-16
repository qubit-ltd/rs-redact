// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Verifies the new layered public entry points retain existing behavior.

use qubit_redact::RedactionEvent;
use qubit_redact::config::RedactionConfig;
use qubit_redact::facade::Redactor;
use qubit_redact::output::RedactedText;

#[test]
fn test_layered_config_and_event_preserve_scalar_redaction() {
    let redactor = Redactor::new(RedactionConfig::standard());
    let mut event: RedactionEvent<'_> = redactor.event();
    let result = event.redact_at(qubit_redact::Sensitivity::Secret, "raw");

    let _: &RedactedText<'_> = &result;
    assert_eq!(result.as_str(), "<redacted>");
}
