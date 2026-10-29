// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Constant-state traversal of strict multipart framing.

/// Iterates non-blank multipart segments borrowed from a validated body.
///
/// Construction scans the complete framing, including the closing delimiter
/// and whitespace-only epilogue, before resetting the cursor for replay.
#[derive(Clone)]
pub(in crate::formats::http) struct MultipartSegments<'a> {
    /// Complete body retained for the lifetime of yielded segment slices.
    bytes: &'a [u8],
    /// Opening delimiter including its `--` prefix.
    delimiter: String,
    /// Closing delimiter including its `--` prefix and closing suffix.
    closing: String,
    /// Byte offset from which the next logical line is scanned.
    scan_position: usize,
    /// Start offset of the current segment body, or `None` before its opening
    /// delimiter.
    segment_start: Option<usize>,
    /// Whether iteration has reached its terminal state.
    finished: bool,
    /// Whether the completed pass found a closing delimiter followed only by
    /// whitespace.
    framing_valid: bool,
}

impl<'a> MultipartSegments<'a> {
    /// Validates the complete framing, then returns a fresh replay iterator.
    ///
    /// The validation pass consumes the temporary cursor through the closing
    /// delimiter and checks the epilogue. On success, all cursor state is
    /// reset so iteration performs a second pass over the same borrowed body.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Complete bounded multipart body.
    /// * `boundary` - Validated delimiter boundary without the `--` prefix.
    ///
    /// # Returns
    ///
    /// A constant-state borrowed iterator, or `None` for invalid framing.
    pub(in crate::formats::http) fn new(bytes: &'a [u8], boundary: &str) -> Option<Self> {
        let delimiter = format!("--{boundary}");
        let closing = format!("{delimiter}--");
        let mut segments = Self {
            bytes,
            delimiter,
            closing,
            scan_position: 0,
            segment_start: None,
            finished: false,
            framing_valid: false,
        };
        for _ in &mut segments {}
        if !segments.framing_valid {
            return None;
        }
        segments.scan_position = 0;
        segments.segment_start = None;
        segments.finished = false;
        segments.framing_valid = false;
        Some(segments)
    }

    /// Classifies a line as a delimiter after trimming trailing spaces/tabs.
    ///
    /// `None` means the line is not a recognized delimiter (including a
    /// non-UTF-8 line), `Some(false)` is an opening delimiter, and
    /// `Some(true)` is the closing delimiter.
    fn delimiter_at(&self, start: usize, end: usize) -> Option<bool> {
        let line = std::str::from_utf8(&self.bytes[start..end]).ok()?;
        let line = line.trim_end_matches([' ', '\t']);
        if line == self.delimiter {
            Some(false)
        } else if line == self.closing {
            Some(true)
        } else {
            None
        }
    }
}

impl<'a> Iterator for MultipartSegments<'a> {
    type Item = &'a [u8];

    /// Returns the next non-whitespace segment as a slice of the source body.
    ///
    /// A malformed closing epilogue terminates iteration with `None`; the
    /// constructor's full validation pass normally detects it before replay.
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        while self.scan_position < self.bytes.len() {
            let (line_start, line_end, next) = next_line(self.bytes, self.scan_position);
            let closing = self.delimiter_at(line_start, line_end);
            self.scan_position = next;
            let Some(closing) = closing else {
                continue;
            };
            let part = self
                .segment_start
                .take()
                .map(|start| strip_line_ending(&self.bytes[start..line_start]));
            if closing {
                self.finished = true;
                self.framing_valid = self.bytes[next..].iter().all(u8::is_ascii_whitespace);
                if !self.framing_valid {
                    return None;
                }
            } else {
                self.segment_start = Some(next);
            }
            if let Some(part) = part.filter(|part| !part.iter().all(u8::is_ascii_whitespace)) {
                return Some(part);
            }
            if closing {
                return None;
            }
        }
        self.finished = true;
        None
    }
}

/// Finds the next logical line's content bounds and the following byte offset.
///
/// A CR immediately before LF is excluded from the content range; an
/// unterminated final line ends at `bytes.len()`.
#[inline]
fn next_line(bytes: &[u8], position: usize) -> (usize, usize, usize) {
    if let Some(relative) = bytes[position..].iter().position(|byte| *byte == b'\n') {
        let end = position + relative;
        let trimmed = end.checked_sub(1).filter(|index| bytes[*index] == b'\r').unwrap_or(end);
        (position, trimmed, end + 1)
    } else {
        (position, bytes.len(), bytes.len())
    }
}

/// Removes one trailing CRLF or LF sequence from a borrowed segment.
#[inline]
fn strip_line_ending(value: &[u8]) -> &[u8] {
    value
        .strip_suffix(b"\r\n")
        .or_else(|| value.strip_suffix(b"\n"))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::MultipartSegments;

    #[test]
    fn test_segments_preserve_strict_framing_cases() {
        let multiple = b"--b \t\r\nfirst\r\n--b\r\n \t\n--b\nsecond\n--b--\n \t";
        let segments = MultipartSegments::new(multiple, "b").expect("framing should be valid");
        assert_eq!(segments.collect::<Vec<_>>(), [b"first".as_slice(), b"second"]);

        let empty = MultipartSegments::new(b"--b--\r\n", "b").expect("empty multipart is valid");
        assert_eq!(empty.count(), 0);

        assert!(MultipartSegments::new(b"--b\r\nfirst\r\n", "b").is_none());
        assert!(MultipartSegments::new(b"--b--\r\nnot-whitespace", "b").is_none());
    }
}
