// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded capture for dynamic debug representations.

use std::fmt;
use std::fmt::Debug;
use std::fmt::Write as _;

pub(in crate::domain) fn bounded_debug<T>(value: &T, maximum: usize) -> (String, bool)
where
    T: Debug + ?Sized,
{
    let mut writer = BoundedCapture::new(maximum);
    let _ = write!(&mut writer, "{value:?}");
    writer.finish()
}

struct BoundedCapture {
    /// Complete UTF-8 fragments accepted so far.
    output: String,
    /// Maximum bytes admitted to the capture.
    maximum: usize,
    /// Whether formatting attempted to exceed the maximum.
    truncated: bool,
}

impl BoundedCapture {
    /// Creates an empty capture with `maximum` admitted bytes.
    fn new(maximum: usize) -> Self {
        Self {
            // `maximum` is an admission limit, not an allocation request.
            output: String::new(),
            maximum,
            truncated: false,
        }
    }

    /// Returns captured text and whether it was truncated.
    fn finish(self) -> (String, bool) {
        (self.output, self.truncated)
    }
}

impl fmt::Write for BoundedCapture {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let mut end = 0;
        for (index, character) in value.char_indices() {
            let next = index + character.len_utf8();
            if next > self.maximum.saturating_sub(self.output.len()) {
                self.truncated = true;
                return Err(fmt::Error);
            }
            end = next;
        }
        self.output.push_str(&value[..end]);
        Ok(())
    }
}
