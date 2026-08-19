// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for HTTP policy, bounded input, and safe output types.

mod support;

mod body_capture_error_tests;
mod body_capture_tests;
mod field_redactor_tests;
mod http_redaction_policy_builder_tests;
mod http_redaction_policy_parts_tests;
mod http_redaction_policy_tests;
mod http_redactor;
mod internal;
mod mod_tests;
mod text_body_policy_tests;
mod unkeyed_json_value_policy_tests;
mod url_path_policy_tests;
