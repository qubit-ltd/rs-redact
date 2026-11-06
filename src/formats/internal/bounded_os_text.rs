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

#[cfg(not(any(unix, windows)))]
use self::bounded::Bounded;

// Implements the bounded formatting sink for other operating systems.
#[cfg(not(any(unix, windows)))]
mod bounded;

/// Converts an OS string lossily without retaining more than `maximum` bytes.
///
/// # Parameters
///
/// - `value`: The operating-system string to convert.
/// - `maximum`: The maximum number of UTF-8 bytes to retain.
///
/// # Returns
///
/// The retained text and a boolean that is true when the complete lossy
/// representation does not fit. The byte limit bounds retained output, not the
/// amount of source examined. On Unix, UTF-8 validation may scan the remaining
/// input before an output-limit rejection is detected.
#[must_use]
pub(crate) fn capture(value: &OsStr, maximum: usize) -> (String, bool) {
    let mut output = String::with_capacity(maximum.min(1024));
    #[cfg(unix)]
    let complete = capture_utf8_lossy(value.as_encoded_bytes(), maximum, &mut output);
    #[cfg(windows)]
    let complete = capture_utf16_lossy(value.encode_wide(), maximum, &mut output);
    #[cfg(not(any(unix, windows)))]
    let complete = write_display(value, maximum, &mut output);
    // Internal helpers report completeness; the tuple reports truncation.
    (output, !complete)
}

/// Converts UTF-8 bytes lossily while retaining only complete chunks within the
/// byte limit.
///
/// # Parameters
///
/// - `bytes`: Source bytes, which may contain invalid UTF-8.
/// - `maximum`: The total byte limit for the destination string.
/// - `output`: The destination to append complete UTF-8 chunks to.
///
/// # Returns
///
/// Returns `true` when all source content was appended. A failed valid chunk is
/// rejected whole; inspecting the remaining input may scan beyond the output
/// limit.
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

/// Decodes UTF-16 one scalar at a time, replacing isolated surrogates with
/// U+FFFD.
///
/// # Parameters
///
/// - `value`: Source UTF-16 code units, which may contain isolated surrogates.
/// - `maximum`: The total byte limit for the destination string.
/// - `output`: The destination to append complete UTF-8 chunks to.
///
/// # Returns
///
/// Returns `false` as soon as a decoded character cannot be appended within
/// the byte limit; otherwise returns `true` after consuming the iterator.
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

/// Formats an OS string through a writer bounded by the output byte limit.
///
/// # Parameters
///
/// - `value`: The operating-system string to format.
/// - `maximum`: The total byte limit for the destination string.
/// - `output`: The destination to append complete UTF-8 chunks to.
///
/// # Returns
///
/// Returns `false` only when capacity rejects a write. This does not provide
/// an independent classification for formatting errors.
#[cfg(not(any(unix, windows)))]
fn write_display(value: &OsStr, maximum: usize, output: &mut String) -> bool {
    let mut writer = Bounded {
        output,
        maximum,
        exceeded: false,
    };
    let _ = write!(&mut writer, "{}", value.display());
    !writer.exceeded
}

/// Appends a whole string slice if its byte length fits the remaining capacity.
///
/// # Parameters
///
/// - `output`: The destination string to append to.
/// - `text`: The complete slice to append or reject.
/// - `maximum`: The total byte limit for the destination string.
///
/// # Returns
///
/// Returns `true` when the slice was accepted and appended; otherwise leaves
/// the output unchanged. Capacity arithmetic saturates on overflow.
#[inline]
fn append_bounded(output: &mut String, text: &str, maximum: usize) -> bool {
    if output.len().saturating_add(text.len()) > maximum {
        return false;
    }
    output.push_str(text);
    true
}
