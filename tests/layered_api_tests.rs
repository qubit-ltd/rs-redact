// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Verifies the new layered public entry points retain existing behavior.

use qubit_redact::config::RedactionConfig;
use qubit_redact::domain::Redact;
use qubit_redact::domain::RedactionWriter;
use qubit_redact::facade::Redactor;

struct Raw;

impl Redact for Raw {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.literal("<redacted>");
    }
}

#[test]
fn test_layered_config_and_redactor_preserve_scalar_redaction() {
    let redactor = Redactor::new(RedactionConfig::standard());
    let result = redactor.redact(&Raw);
    assert_eq!(result.text().as_str(), "<redacted>");
}
