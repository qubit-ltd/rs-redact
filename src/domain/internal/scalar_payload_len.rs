// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Counts the display bytes of native scalar values without a heap buffer.

use std::fmt;

#[derive(Default)]
struct ByteCounter {
    bytes: usize,
}

impl fmt::Write for ByteCounter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.bytes = self.bytes.checked_add(text.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}

/// Returns the UTF-8 byte length produced by a value's `Display` formatter.
///
/// Formatting errors, including a counter overflow, are returned as
/// `fmt::Error`. The writer stores only a byte count and does not allocate.
pub(super) fn scalar_payload_len<T: fmt::Display>(value: T) -> Result<usize, fmt::Error> {
    let mut counter = ByteCounter::default();
    fmt::write(&mut counter, format_args!("{value}"))?;
    Ok(counter.bytes)
}
