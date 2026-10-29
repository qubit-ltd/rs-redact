// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded lossy conversion for operating-system strings.

use std::ffi::OsStr;
#[cfg(not(any(unix, windows)))]
use std::fmt::Write as _;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

/// Converts an OS string lossily without retaining more than `maximum` bytes.
///
/// The returned boolean is true when the complete lossy representation did
/// not fit. Decoding stops as soon as the output limit is crossed.
#[must_use]
pub(crate) fn capture(value: &OsStr, maximum: usize) -> (String, bool) {
    let mut output = String::with_capacity(maximum.min(1024));
    #[cfg(unix)]
    let complete = capture_utf8_lossy(value.as_encoded_bytes(), maximum, &mut output);
    #[cfg(windows)]
    let complete = capture_utf16_lossy(value.encode_wide(), maximum, &mut output);
    #[cfg(not(any(unix, windows)))]
    let complete = write_display(value, maximum, &mut output);
    (output, !complete)
}

#[cfg(unix)]
fn capture_utf8_lossy(bytes: &[u8], maximum: usize, output: &mut String) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        match std::str::from_utf8(&bytes[offset..]) {
            Ok(valid) => return append_bounded(output, valid, maximum),
            Err(error) => {
                let valid_end = offset + error.valid_up_to();
                let valid = std::str::from_utf8(&bytes[offset..valid_end])
                    .expect("valid_up_to identifies a valid UTF-8 prefix");
                if !append_bounded(output, valid, maximum) {
                    return false;
                }
                offset = valid_end;
                if let Some(error_len) = error.error_len() {
                    if !append_bounded(output, "�", maximum) {
                        return false;
                    }
                    offset += error_len;
                } else {
                    return append_bounded(output, "�", maximum);
                }
            }
        }
    }
    true
}

#[cfg(windows)]
fn capture_utf16_lossy(value: impl Iterator<Item = u16>, maximum: usize, output: &mut String) -> bool {
    for decoded in char::decode_utf16(value) {
        let character = decoded.unwrap_or(char::REPLACEMENT_CHARACTER);
        let mut encoded = [0; 4];
        if !append_bounded(output, character.encode_utf8(&mut encoded), maximum) {
            return false;
        }
    }
    true
}

#[cfg(not(any(unix, windows)))]
fn write_display(value: &OsStr, maximum: usize, output: &mut String) -> bool {
    struct Bounded<'a> {
        output: &'a mut String,
        maximum: usize,
        exceeded: bool,
    }
    impl std::fmt::Write for Bounded<'_> {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            if !append_bounded(self.output, text, self.maximum) {
                self.exceeded = true;
                return Err(std::fmt::Error);
            }
            Ok(())
        }
    }
    let mut writer = Bounded {
        output,
        maximum,
        exceeded: false,
    };
    let _ = write!(&mut writer, "{}", value.display());
    !writer.exceeded
}

fn append_bounded(output: &mut String, text: &str, maximum: usize) -> bool {
    if output.len().saturating_add(text.len()) > maximum {
        return false;
    }
    output.push_str(text);
    true
}
