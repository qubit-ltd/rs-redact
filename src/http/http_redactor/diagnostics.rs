// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared budget and log-boundary helpers for HTTP diagnostics.

use std::borrow::Cow;

use crate::LogSafeText;

use super::HttpRedactor;
use crate::http::internal::{
    BoundedLogWriter,
    markers,
};

impl HttpRedactor {
    /// Reports whether a diagnostic input exceeds the hard input limit.
    pub(super) fn diagnostic_input_exceeded(&self, input_bytes: usize) -> bool {
        input_bytes > self.policy().diagnostic_budget().max_input_bytes()
    }

    /// Returns the fixed log-safe diagnostic-limit marker.
    pub(super) fn diagnostic_limit_exceeded() -> LogSafeText<'static> {
        LogSafeText::from_escaped(Cow::Borrowed(
            markers::DIAGNOSTIC_LIMIT_EXCEEDED,
        ))
    }

    /// Escapes and bounds one redacted HTTP diagnostic.
    pub(super) fn finish_diagnostic(
        &self,
        text: String,
    ) -> LogSafeText<'static> {
        let mut writer = BoundedLogWriter::new(
            self.policy().diagnostic_budget().max_output_bytes(),
            false,
        );
        let _ = writer.write_str(&text);
        let (text, _) = writer.finish();
        LogSafeText::from_escaped(Cow::Owned(text))
    }
}
