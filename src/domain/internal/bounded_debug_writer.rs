// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded adapter for streaming debug fragments into a domain writer.

use std::fmt;

use crate::domain::RedactionWriter;

/// `fmt::Write` adapter that stops a `Debug` formatter at the writer's final
/// escaped-output ceiling instead of first materializing an unbounded string.
pub(in crate::domain) struct BoundedDebugWriter<'writer, 'session> {
    /// Domain writer receiving complete formatter fragments.
    pub(in crate::domain) writer: &'writer mut RedactionWriter<'session>,
}

impl fmt::Write for BoundedDebugWriter<'_, '_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.writer.write_fragment(value) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}
