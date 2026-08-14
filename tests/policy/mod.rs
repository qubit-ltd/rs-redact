// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for redaction policy primitives.

mod allow_rule_tests;
mod diagnostic_budget_error_tests;
mod diagnostic_budget_runtime_tests;
mod diagnostic_budget_tests;
mod diagnostic_input_budget_tests;
mod field_classification_tests;
mod field_match_kind_tests;
mod field_name_matching_tests;
mod internal;
mod mask_policy_tests;
mod masking_policy_tests;
mod mod_tests;
mod policy_error_tests;
mod policy_location_tests;
mod redaction_floor_builder_tests;
mod redaction_floor_tests;
mod redaction_limits_tests;
mod redaction_policy_builder_tests;
mod redaction_policy_tests;
mod redaction_resource_tests;
mod redaction_rules_builder_tests;
mod redaction_rules_tests;
mod redaction_session_tests;
mod resolved_field_tests;
mod sensitive_field_preset_tests;
mod sensitive_field_rule_tests;
mod sensitivity_tests;
mod unified_policy_tests;
mod unknown_field_policy_tests;
