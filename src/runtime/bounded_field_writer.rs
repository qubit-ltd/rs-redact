// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded log-safe field rendering for one transaction fragment.

use std::fmt;

use super::OperationSink;
use crate::RedactionReason;

/// Streams one field through log escaping without exceeding its output limit.
pub(crate) struct BoundedFieldWriter {
    sink: OperationSink,
}

impl BoundedFieldWriter {
    /// Creates an empty writer bounded by `max_output_bytes`.
    pub(crate) fn new(max_output_bytes: usize) -> Self {
        Self {
            sink: OperationSink::new(max_output_bytes, "", false),
        }
    }

    /// Reports whether a write exceeded the configured output limit.
    pub(crate) const fn overflowed(&self) -> bool {
        self.sink.output_truncated()
    }

    /// Returns the completed escaped output.
    pub(crate) fn finish(self) -> String {
        let (text, _, _) = self
            .sink
            .finish_with_reason(RedactionReason::OutputLimitReached)
            .into_parts();
        text
    }
}

impl fmt::Write for BoundedFieldWriter {
    /// Writes log-safe text until the configured byte limit is reached.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.sink.write_log_safe(value)?;
        if self.sink.output_truncated() {
            return Err(fmt::Error);
        }
        Ok(())
    }
}
