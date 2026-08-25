// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime-owned byte sink for incrementally serialized safe text.

use std::io;
use std::io::Write;

/// Bounds serializer output before it becomes an unpublished operation.
pub(crate) struct OperationByteSink {
    /// Serializer bytes retained only after complete-token admission.
    output: Vec<u8>,
    /// Maximum bytes the operation may retain.
    maximum: usize,
}

impl OperationByteSink {
    /// Creates an empty byte sink with one operation's output allowance.
    #[must_use]
    pub(crate) const fn new(maximum: usize) -> Self {
        Self {
            output: Vec::new(),
            maximum,
        }
    }

    /// Converts accepted serializer bytes into UTF-8 text.
    #[must_use]
    pub(crate) fn into_string(self) -> Option<String> {
        String::from_utf8(self.output).ok()
    }
}

impl Write for OperationByteSink {
    /// Atomically appends `buffer` when the complete serializer token fits.
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.output.len().saturating_add(buffer.len()) > self.maximum {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    /// Flushes the in-memory serializer sink.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
