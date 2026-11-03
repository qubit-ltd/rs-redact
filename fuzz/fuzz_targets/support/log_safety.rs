// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Independent log-output safety oracle for fuzz targets and regressions.

/// Rejects raw characters that can alter log structure or visual ordering.
pub fn assert_log_safe(text: &str) {
    assert!(
        !text.chars().any(|c| {
            c.is_control()
                || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}'
                | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        }),
        "raw log-unsafe character in output"
    );
}
