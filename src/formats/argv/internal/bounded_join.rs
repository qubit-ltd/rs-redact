// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

//! Bounded string joining for argument-vector redaction.

/// Joins string slices only when their combined UTF-8 length fits the limit.
///
/// Returns an empty string and `true` if the length overflows or exceeds the
/// limit. Otherwise, allocates exactly the combined length and returns `false`
/// as the truncation flag.
pub(crate) fn join_bounded(parts: &[&str], limit: usize) -> (String, bool) {
    let Some(length) = parts
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(part.len()))
    else {
        return (String::new(), true);
    };
    if length > limit {
        return (String::new(), true);
    }
    let mut output = String::with_capacity(length);
    for part in parts {
        output.push_str(part);
    }
    (output, false)
}
