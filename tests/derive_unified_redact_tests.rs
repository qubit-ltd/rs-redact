// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

//! Runtime coverage for the unified borrowing `Redact` derive.

#![cfg(feature = "derive")]

mod support;

#[test]
fn named_tuple_enum_and_formatting_contracts_work() {
    support::assertions::assert_named_redaction();
    support::assertions::assert_tuple_redaction();
    support::assertions::assert_enum_redaction();
    support::assertions::assert_format_expansion();
}

#[test]
fn policy_admission_depth_and_sensitivity_contracts_work() {
    support::assertions::assert_field_admission_precedes_access();
    support::assertions::assert_nested_admission_uses_shared_session();
    support::assertions::assert_sensitivity_expansion();
}

#[cfg(feature = "serde")]
#[test]
fn structured_serde_and_adapters_work() {
    support::assertions::assert_serde_expansion();
    support::assertions::assert_serde_adapter_expansion();
}

#[cfg(feature = "json")]
#[test]
fn json_string_mode_preserves_its_wire_type() {
    support::assertions::assert_json_expansion();
}
// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
