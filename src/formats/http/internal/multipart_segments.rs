// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Constant-state traversal of strict multipart framing.

/// Borrows multipart segments after validating the complete framing.
#[derive(Clone)]
pub(in crate::formats::http) struct MultipartSegments<'a> {
    bytes: &'a [u8],
    delimiter: String,
    closing: String,
    scan_position: usize,
    segment_start: Option<usize>,
    finished: bool,
    framing_valid: bool,
}

impl<'a> MultipartSegments<'a> {
    /// Validates all delimiters and the epilogue before returning a fresh
    /// iterator.
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

/// Finds the next logical line bounds.
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
