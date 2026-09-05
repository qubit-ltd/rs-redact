// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile tests for supported `Redact` derive inputs.

#![cfg(all(feature = "derive", feature = "serde"))]

/// Verifies that all supported derive fixtures compile successfully.
#[test]
fn test_pass_fixtures() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/fixtures/pass/new_contract.rs");
    tests.pass("tests/fixtures/pass/basic_named_struct.rs");
    tests.pass("tests/fixtures/pass/enum_variants.rs");
    tests.pass("tests/fixtures/pass/level_and_skip.rs");
    tests.pass("tests/fixtures/pass/safe_formatting.rs");
    tests.pass("tests/fixtures/pass/serde_coverage_shapes.rs");
    tests.pass("tests/fixtures/pass/serde_deserialize_only.rs");
    tests.pass("tests/fixtures/pass/tuple_and_unit_structs.rs");
    tests.pass("tests/fixtures/pass/generic_serializer_name.rs");
    tests.pass("tests/fixtures/pass/readme_quick_start.rs");
    tests.pass("tests/fixtures/pass/recursive_level_containers.rs");
    tests.pass("tests/fixtures/pass/nested_container_serde.rs");
    tests.pass("tests/fixtures/pass/disabled_fields.rs");
    tests.pass("tests/fixtures/pass/serde_wire_shape.rs");
    tests.pass("tests/fixtures/pass/generic_grouped_bounds.rs");
    tests.pass("tests/fixtures/pass/keyed_by.rs");
    #[cfg(feature = "json")]
    tests.pass("tests/fixtures/pass/json_string_variants.rs");
}

/// Verifies that invalid attributes produce stable targeted diagnostics.
#[test]
fn test_compile_fail_fixtures() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/fixtures/fail/conflicting_level_map.rs");
    tests.compile_fail("tests/fixtures/fail/conflicting_level_nested.rs");
    tests.compile_fail("tests/fixtures/fail/conflicting_map_skip.rs");
    tests.compile_fail("tests/fixtures/fail/conflicting_modes.rs");
    tests.compile_fail("tests/fixtures/fail/debug_trait_conflict.rs");
    tests.compile_fail("tests/fixtures/fail/duplicate_attribute.rs");
    tests.compile_fail("tests/fixtures/fail/duplicate_debug_option.rs");
    tests.compile_fail("tests/fixtures/fail/empty_attribute.rs");
    tests.compile_fail("tests/fixtures/fail/invalid_container_attributes.rs");
    tests.compile_fail("tests/fixtures/fail/invalid_field_attribute_arguments.rs");
    tests.compile_fail("tests/fixtures/fail/invalid_serde_container_attributes.rs");
    tests.compile_fail("tests/fixtures/fail/invalid_serde_field_attributes.rs");
    tests.compile_fail("tests/fixtures/fail/invalid_serde_variant_attributes.rs");
    tests.compile_fail("tests/fixtures/fail/removed_attributes.rs");
    tests.compile_fail("tests/fixtures/fail/level_struct.rs");
    tests.compile_fail("tests/fixtures/fail/sensitive_serde_adapter.rs");
    tests.compile_fail("tests/fixtures/fail/map_wrong_key.rs");
    tests.compile_fail("tests/fixtures/fail/keyed_by_missing.rs");
    tests.compile_fail("tests/fixtures/fail/keyed_by_self.rs");
    tests.compile_fail("tests/fixtures/fail/keyed_by_tuple.rs");
    tests.compile_fail("tests/fixtures/fail/keyed_by_wrong_key.rs");
    tests.compile_fail("tests/fixtures/fail/nested_without_redact_serialize.rs");
    tests.compile_fail("tests/fixtures/fail/union.rs");
    tests.compile_fail("tests/fixtures/fail/unknown_attribute.rs");
    tests.compile_fail("tests/fixtures/fail/unknown_level.rs");
}
