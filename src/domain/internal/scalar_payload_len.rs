// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Counts the display bytes of native scalar values without a heap buffer.

use std::fmt;

use self::byte_counter::ByteCounter;

// Implements the allocation-free formatting sink used by the length
// calculation.
mod byte_counter;

/// Returns the UTF-8 byte length produced by a value's `Display` formatter.
///
/// Formatting errors, including a counter overflow, are returned as
/// `fmt::Error`. The writer stores only a byte count and does not allocate.
///
/// # Type Parameters
///
/// - `T`: A value whose `Display` implementation supplies the text to count.
///
/// # Parameters
///
/// - `value`: The value consumed by this call and borrowed while formatting.
///
/// # Returns
///
/// The number of UTF-8 bytes emitted by the formatter on success.
///
/// # Errors
///
/// Returns `fmt::Error` if formatting fails or the byte count exceeds
/// `usize::MAX`.
pub(super) fn scalar_payload_len<T: fmt::Display>(value: T) -> Result<usize, fmt::Error> {
    let mut counter = ByteCounter::default();
    fmt::write(&mut counter, format_args!("{value}"))?;
    Ok(counter.bytes)
}
