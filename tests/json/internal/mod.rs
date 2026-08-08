// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests covering JSON traversal internals through their public behavior.

#[cfg(feature = "http")]
mod json_redaction_outcome_tests;
mod json_redaction_state_tests;
#[cfg(feature = "http")]
mod json_unkeyed_value_policy_tests;
