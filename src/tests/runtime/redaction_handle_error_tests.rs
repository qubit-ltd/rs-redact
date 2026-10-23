// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Crate-internal diagnostics for unpublished runtime handle errors.

use crate::RedactionHandleError;

/// Handle errors render stable diagnostics without incorporating handle
/// data.
#[test]
fn test_handle_error_display_messages() {
    assert_eq!(
        RedactionHandleError::DifferentTransaction.to_string(),
        "the handle belongs to a different transaction"
    );
    assert_eq!(
        RedactionHandleError::MissingItem.to_string(),
        "the handle does not identify a published item"
    );
}
