// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded display adapter for log-safe text.

use std::fmt::{
    self,
    Display,
    Formatter,
    Write as _,
};

use super::{
    LogOutputLimit,
    LogSafeText,
    internal::BoundedLogEscapeWriter,
};

/// A byte-bounded rendering of text that is already safe for a log boundary.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed log-safe text.
#[must_use = "format the bounded log-safe text"]
pub struct BoundedLogSafeDisplay<'a> {
    /// Escaped source text.
    value: &'a LogSafeText<'a>,
    /// Validated rendered output limit.
    limit: LogOutputLimit,
}

impl<'a> BoundedLogSafeDisplay<'a> {
    /// Creates a bounded view of already escaped log-safe text.
    ///
    /// # Parameters
    ///
    /// * `value` - Escaped source text to render.
    /// * `limit` - Validated final output-byte limit.
    ///
    /// # Returns
    ///
    /// A borrowed bounded display adapter.
    #[inline(always)]
    pub(super) const fn new(
        value: &'a LogSafeText<'a>,
        limit: LogOutputLimit,
    ) -> Self {
        Self { value, limit }
    }
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
