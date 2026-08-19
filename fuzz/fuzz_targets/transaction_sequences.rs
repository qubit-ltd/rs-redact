// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
#![no_main]

use libfuzzer_sys::fuzz_target;
use qubit_redact::RedactionHandleError;
use qubit_redact::Redactor;

// Exercises reusable session transaction boundaries with arbitrary operation
// sequences. Published output must remain UTF-8 and isolated from handles
// created by earlier transactions.
fuzz_target!(|data: &[u8]| {
    let mut session = Redactor::standard().session();
    let mut previous_handle = None;
    for chunk in data.chunks(3).take(128) {
        let selector = chunk.first().copied().unwrap_or_default();
        let value = String::from_utf8_lossy(chunk);
        match selector % 3 {
            0 => {
                let _ = session.literal("event=").field("name", &value);
            }
            1 => {
                previous_handle = Some(session.redact_field("password", &value));
            }
            _ => {
                let output = session.finish();
                assert!(std::str::from_utf8(output.text().as_str().as_bytes()).is_ok());
                if let Some(handle) = previous_handle.take() {
                    let _ = output.resolve(handle);
                }
            }
        }
    }
    let output = session.finish();
    if let Some(handle) = previous_handle {
        assert!(matches!(
            output.resolve(handle),
            Ok(_) | Err(RedactionHandleError::DifferentTransaction)
        ));
    }
    assert!(std::str::from_utf8(output.text().as_str().as_bytes()).is_ok());
});
