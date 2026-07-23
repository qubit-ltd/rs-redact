// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for internal model composition.

use crate::support;

/// Verifies internal model components compose for an enum.
#[test]
fn test_internal_model_components_compose() {
    support::assertions::assert_enum_redaction();
}
