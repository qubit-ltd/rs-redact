// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for JSON depth limit validation errors.

use qubit_redact::JsonDepthLimitError;
fn test_json_depth_limit_error_is_descriptive() {
    assert_eq!(
        JsonDepthLimitError::ZeroDepth.to_string(),
        "JSON depth limit must be greater than zero",
    );
}
