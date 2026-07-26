// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded display adapter for log-safe text.

use std::fmt::{self, Display, Formatter, Write as _};

use super::{LogOutputLimit, LogSafeText, internal::BoundedLogEscapeWriter};

/// A byte-bounded rendering of text that is already safe for a log boundary.
#[must_use = "format the bounded log-safe text"]
pub struct BoundedLogSafeDisplay<'a> {
    /// Escaped source text.
    value: &'a LogSafeText<'a>,
    /// Validated rendered output limit.
    limit: LogOutputLimit,
}

impl<'a> BoundedLogSafeDisplay<'a> {
    /// Creates a bounded view of already escaped log-safe text.
    #[inline(always)]
    pub(super) const fn new(value: &'a LogSafeText<'a>, limit: LogOutputLimit) -> Self {
        Self { value, limit }
    }
}

impl Display for BoundedLogSafeDisplay<'_> {
    /// Writes the escaped source text without exceeding the output limit.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = BoundedLogEscapeWriter::new(self.limit);
        if writer.write_str(self.value.as_str()).is_err() && !writer.is_truncated() {
            return Err(fmt::Error);
        }
        formatter.write_str(&writer.finish())
    }
}
