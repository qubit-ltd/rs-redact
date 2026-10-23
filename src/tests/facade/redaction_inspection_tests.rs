// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for conclusive sensitivity inspection metadata.

use crate::RedactionInspection;
use crate::RedactionUsage;
use crate::Sensitivity;

#[test]
fn test_inspection_queries_report_sensitive_and_disabled_states() {
    let sensitive = RedactionInspection::new(false, Some(Sensitivity::High), RedactionUsage::empty());
    assert!(sensitive.contains_sensitive());
    assert!(!sensitive.is_redaction_disabled());
    assert_eq!(sensitive.max_sensitivity(), Some(Sensitivity::High));

    let disabled = RedactionInspection::new(true, None, RedactionUsage::empty());
    assert!(!disabled.contains_sensitive());
    assert!(disabled.is_redaction_disabled());
    assert_eq!(disabled.max_sensitivity(), None);
}
