// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded display adapter for log-safe text.

use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Write as _;

use super::LogOutputLimit;
use super::RedactedText;
use super::internal::BoundedLogEscapeWriter;

/// A byte-bounded rendering of text that is already safe for a log boundary.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed log-safe text.
pub struct BoundedLogSafeDisplay<'a> {
    /// Escaped source text.
    value: &'a RedactedText,
    /// Validated rendered output limit.
    limit: LogOutputLimit,
}

impl Display for BoundedLogSafeDisplay<'_> {
    /// Writes the escaped source text without exceeding the output limit.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result after writing bounded escaped text.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter rejects output.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = BoundedLogEscapeWriter::new(self.limit);
        // The internal writer uses `fmt::Error` only to stop after recording
        // truncation; `finish` renders that state with a complete marker.
        let _ = writer.write_str(self.value.as_str());
        formatter.write_str(&writer.finish())
    }
}
