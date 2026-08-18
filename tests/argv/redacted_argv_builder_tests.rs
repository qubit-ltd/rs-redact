// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;
use qubit_redact::formats::argv::ArgvRedactor;
/// Direct argv adapters do not apply the removed shared byte budget.
#[test]
fn test_redacted_argv_builder_processes_input() {
    let rendered = ArgvRedactor::new(Redactor::new(RedactionPolicy::standard()))
        .redact_items([ArgvItem::plain(OsStr::new("uninspected-secret"))])
        .to_string();

    assert_eq!(rendered, r#"["uninspected-secret"]"#);
}
