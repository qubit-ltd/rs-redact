// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
use std::fmt::Write;

#[cfg(not(test))]
use http::HeaderValue;
#[cfg(not(test))]
use libfuzzer_sys::fuzz_target;
#[cfg(not(test))]
use qubit_redact::RedactionReason;
#[cfg(not(test))]
use qubit_redact::RedactionTextOutput;
#[cfg(not(test))]
use qubit_redact::Redactor;
#[cfg(not(test))]
use qubit_redact::formats::http::BodyCapture;

const FUZZ_SECRET: &str = "multipart-fuzz-secret-b08761d5";
const MAX_DIRECTED_CUTS: usize = 24;

/// Encodes arbitrary bytes as inert multipart text.
#[must_use]
#[cfg(not(test))]
fn encoded_noise(input: &[u8]) -> String {
    let mut encoded = String::with_capacity(input.len().saturating_mul(2));
    for byte in input.iter().take(2_048) {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// Selects a deterministic cut anywhere from the empty prefix to the full body.
#[must_use]
fn random_cut(input: &[u8], body_len: usize) -> usize {
    let mut word = [0_u8; 8];
    let count = input.len().min(word.len());
    word[..count].copy_from_slice(&input[..count]);
    (u64::from_le_bytes(word) % (body_len as u64 + 1)) as usize
}

/// Returns a bounded set of cuts around semantic multipart boundaries.
#[must_use]
fn directed_cuts(body: &str, boundary: &str) -> Vec<usize> {
    let secret_start = body.find(FUZZ_SECRET);
    let upload_start = body.rfind(FUZZ_SECRET);
    let password_part = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"password\"");
    let closing_marker = format!("--{boundary}--");
    let closing_start = body.rfind(&closing_marker);
    let anchors = [
        body.find(&password_part),
        secret_start,
        secret_start.map(|start| start + FUZZ_SECRET.len()),
        upload_start,
        upload_start.map(|start| start + FUZZ_SECRET.len()),
        closing_start,
        closing_start.map(|start| start + closing_marker.len()),
        Some(body.len()),
    ];
    let mut cuts = Vec::with_capacity(MAX_DIRECTED_CUTS);
    for anchor in anchors.into_iter().flatten() {
        for cut in [
            anchor.saturating_sub(1),
            anchor,
            anchor.saturating_add(1).min(body.len()),
        ] {
            cuts.push(cut);
        }
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts.truncate(MAX_DIRECTED_CUTS);
    cuts
}

#[cfg(not(test))]
/// Checks the publication invariants shared by every fuzzed operation.
fn assert_output_invariants(output: &RedactionTextOutput, max_output_bytes: usize) {
    let text = output.text().as_str();
    assert!(text.len() <= max_output_bytes);
    assert!(!text.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            )
    }));
}

#[cfg(not(test))]
fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(4_096)];
    let redactor = Redactor::standard();
    let max_output_bytes = redactor.policy().limits().max_output_bytes();
    let boundary = format!("qubit-fuzz-{}", encoded_noise(input.get(..16).unwrap_or(input)));
    let content_type = HeaderValue::from_str(&format!("multipart/form-data; boundary={boundary}"))
        .expect("hex-encoded boundary must be valid");

    let first = redactor.redact_http_body(BodyCapture::complete(input), Some(&content_type));
    let second = redactor.redact_http_body(BodyCapture::complete(input), Some(&content_type));
    assert_eq!(first, second);
    assert_output_invariants(&first, max_output_bytes);

    let noise = encoded_noise(input);
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"note\"\r\n\r\n\
         {noise}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"password\"\r\n\r\n\
         {FUZZ_SECRET}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"upload\"; filename=\"secret.txt\"\r\n\
         X-Fuzz-Part: {noise}\r\n\
         Content-Type: application/octet-stream\r\n\r\n\
         {FUZZ_SECRET}\r\n\
         --{boundary}--\r\n"
    );
    let output = redactor.redact_http_body(BodyCapture::complete(body.as_bytes()), Some(&content_type));
    assert_output_invariants(&output, max_output_bytes);
    assert!(!output.text().as_str().contains(FUZZ_SECRET));

    let mut cuts = directed_cuts(&body, &boundary);
    cuts.push(random_cut(input, body.len()));
    cuts.sort_unstable();
    cuts.dedup();
    for retained in cuts {
        let capture = if retained == body.len() {
            BodyCapture::complete(body.as_bytes())
        } else {
            BodyCapture::prefix(body.as_bytes(), retained)
        };
        let output = redactor.redact_http_body(capture, Some(&content_type));
        assert_output_invariants(&output, max_output_bytes);
        assert!(!output.text().as_str().contains(FUZZ_SECRET));
        assert_eq!(
            output.summary().reasons().contains(RedactionReason::SourceTruncated),
            retained < body.len(),
        );
    }
});

#[cfg(test)]
mod tests {
    use super::directed_cuts;
    use super::random_cut;

    #[test]
    fn random_cut_uses_full_word_and_includes_body_end() {
        assert_eq!(random_cut(&1_024_u64.to_le_bytes(), 5_000), 1_024);
        assert_eq!(random_cut(&[], 5_000), 0);
        assert_eq!(random_cut(&5_000_u64.to_le_bytes(), 5_000), 5_000);
        assert!(random_cut(&u64::MAX.to_le_bytes(), 5_000) <= 5_000);
    }

    #[test]
    fn directed_cuts_cover_semantic_boundaries_with_a_fixed_bound() {
        let boundary = "fuzz-boundary";
        let secret = "multipart-fuzz-secret-b08761d5";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n{}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{secret}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"secret.txt\"\r\nX-Fuzz-Part: noise\r\nContent-Type: application/octet-stream\r\n\r\n{secret}\r\n--{boundary}--\r\n",
            "x".repeat(300)
        );
        let cuts = directed_cuts(&body, boundary);
        assert!(cuts.len() <= 24);
        assert!(cuts.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(cuts.iter().all(|cut| *cut <= body.len()));
        let password_part = "--fuzz-boundary\r\nContent-Disposition: form-data; name=\"password\"";
        let password_start = body.find(password_part).expect("password part in formatted body");
        assert!(cuts.iter().any(|cut| cut.abs_diff(password_start) <= 1));
        for marker in [secret, "--fuzz-boundary--"] {
            let start = body.find(marker).expect("marker in formatted body");
            let end = start + marker.len();
            assert!(cuts.iter().any(|cut| cut.abs_diff(start) <= 1));
            assert!(cuts.iter().any(|cut| cut.abs_diff(end) <= 1));
        }
        let upload_start = body.rfind(secret).expect("upload content in formatted body");
        let upload_end = upload_start + secret.len();
        assert!(cuts.iter().any(|cut| cut.abs_diff(upload_start) <= 1));
        assert!(cuts.iter().any(|cut| cut.abs_diff(upload_end) <= 1));
        assert!(cuts.iter().any(|cut| *cut > 255));
        assert!(cuts.contains(&body.len()));
    }
}
