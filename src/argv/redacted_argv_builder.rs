// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Streaming construction of bounded redacted argv diagnostics.

use std::fmt::Write as _;

use crate::{
    DiagnosticBudget,
    LogOutputLimit,
    text::internal::BoundedLogEscapeWriter,
};

use super::RedactedArgv;

/// Marker rendered as one argv item after diagnostic input is exhausted.
pub(super) const TRUNCATED_ITEM: &str = "<truncated>";

/// Streams a byte-bounded argv rendering without retaining every token.
pub(super) struct RedactedArgvBuilder {
    /// Escaped destination for the complete debug-style list.
    writer: BoundedLogEscapeWriter,
    /// Whether at least one item has been written.
    has_item: bool,
}

impl RedactedArgvBuilder {
    /// Starts an empty argv rendering with the supplied diagnostic budget.
    pub(super) fn new(budget: DiagnosticBudget) -> Self {
        let limit = LogOutputLimit::new(budget.max_output_bytes())
            .expect("diagnostic budgets always satisfy the log output minimum");
        let mut writer = BoundedLogEscapeWriter::new(limit);
        let _ = writer.write_str("[");
        Self {
            writer,
            has_item: false,
        }
    }

    /// Appends one already redacted token to the bounded debug-style list.
    pub(super) fn push(&mut self, item: &str) -> bool {
        if self.has_item {
            let _ = self.writer.write_str(", ");
        }
        let _ = write!(self.writer, "{item:?}");
        self.has_item = true;
        !self.writer.is_truncated()
    }

    /// Completes the bounded argv rendering.
    pub(super) fn finish(mut self) -> RedactedArgv {
        if !self.writer.is_truncated() {
            let _ = self.writer.write_str("]");
        }
        RedactedArgv::from_rendered(self.writer.finish())
    }
}
