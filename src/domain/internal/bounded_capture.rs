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

/// Formats a debug value while retaining only complete UTF-8 fragments within
/// `maximum` bytes.
///
/// Returns the retained text and whether formatting produced content beyond
/// the limit. The value is formatted once and no partial UTF-8 character is
/// retained.
///
/// # Type Parameters
///
/// - `T`: Possibly unsized source implementing `Debug`.
///
/// # Parameters
///
/// - `value`: Debug representation invoked once.
/// - `maximum`: Atomic UTF-8 fragment allowance.
///
/// # Returns
///
/// Accepted complete fragments and whether any fragment was rejected.
/// An error returned by `Debug` independently of capacity is ignored.
pub(in crate::domain) fn bounded_debug<T>(value: &T, maximum: usize) -> (String, bool)
where
    T: Debug + ?Sized,
{
    let mut writer = BoundedCapture::new(maximum);
    let _ = write!(&mut writer, "{value:?}");
    writer.finish()
}

/// Collects complete debug-output fragments up to a byte limit.
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
    ///
    /// # Parameters
    ///
    /// - `maximum`: Maximum accepted raw UTF-8 bytes.
    ///
    /// # Returns
    ///
    /// An empty capture without truncation.
    #[must_use]
    #[inline(always)]
    fn new(maximum: usize) -> Self {
        Self {
            // `maximum` is an admission limit, not an allocation request.
            output: String::new(),
            maximum,
            truncated: false,
        }
    }

    /// Returns captured text and whether it was truncated.
    ///
    /// # Returns
    ///
    /// Accepted text and whether a fragment exceeded the byte allowance.
    #[must_use]
    #[inline(always)]
    fn finish(self) -> (String, bool) {
        (self.output, self.truncated)
    }
}

impl fmt::Write for BoundedCapture {
    /// Appends `value` only when the complete string fits in the remaining
    /// byte budget; otherwise records truncation and rejects the write.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when this or any earlier fragment exceeds the
    /// allowance. Rejection is permanent, including for later empty writes.
    ///
    /// # Parameters
    ///
    /// - `value`: Atomic UTF-8 fragment offered by the formatter.
    ///
    /// # Returns
    ///
    /// Success after accepting the complete fragment within the remaining byte
    /// allowance.
    #[inline]
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.truncated || value.len() > self.maximum.saturating_sub(self.output.len()) {
            self.truncated = true;
            return Err(fmt::Error);
        }
        self.output.push_str(value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::BoundedCapture;

    /// A custom Debug implementation cannot reopen a rejected capture.
    #[test]
    fn test_rejected_debug_chunk_closes_capture_permanently() {
        let mut capture = BoundedCapture::new(4);
        assert!(capture.write_str("oversized").is_err());
        assert!(capture.write_str("x").is_err());
        let (text, truncated) = capture.finish();
        assert!(text.is_empty());
        assert!(truncated);
    }
}
