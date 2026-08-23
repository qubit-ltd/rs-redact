// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Test-only accounting for JSON parser entry points.

use std::cell::Cell;

thread_local! {
    static JSON_PARSE_COUNT: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn record_json_parse() {
    JSON_PARSE_COUNT.set(JSON_PARSE_COUNT.get().saturating_add(1));
}

pub(super) fn reset_json_parse_count() {
    JSON_PARSE_COUNT.set(0);
}

pub(super) fn json_parse_count() -> usize {
    JSON_PARSE_COUNT.get()
}
