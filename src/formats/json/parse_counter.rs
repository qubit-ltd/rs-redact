// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Test-only accounting for JSON parser entry points.

use std::cell::Cell;

thread_local! {
    static JSON_PARSE_COUNT: Cell<usize> = const { Cell::new(0) };
    static JSON_MATERIALIZATION_COUNT: Cell<usize> = const { Cell::new(0) };
}

/// Records entry into the unique decoder path after shared preflight.
pub(crate) fn record_json_materialization() {
    JSON_MATERIALIZATION_COUNT.set(JSON_MATERIALIZATION_COUNT.get().saturating_add(1));
}

/// Resets the current test thread's unique decoder path-entry count to zero.
pub(crate) fn reset_json_materialization_count() {
    JSON_MATERIALIZATION_COUNT.set(0);
}

/// Returns unique decoder path entries recorded on this test thread.
#[must_use]
pub(crate) fn json_materialization_count() -> usize {
    JSON_MATERIALIZATION_COUNT.get()
}

/// Records one JSON parser entry for the current test thread.
pub(crate) fn record_json_parse() {
    JSON_PARSE_COUNT.set(JSON_PARSE_COUNT.get().saturating_add(1));
}

/// Resets the current test thread's JSON parser-entry count to zero.
pub(crate) fn reset_json_parse_count() {
    JSON_PARSE_COUNT.set(0);
}

/// Returns the JSON parser-entry count recorded by the current test thread.
#[must_use]
pub(crate) fn json_parse_count() -> usize {
    JSON_PARSE_COUNT.get()
}
