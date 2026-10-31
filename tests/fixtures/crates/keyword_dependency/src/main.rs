// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use r#type::Redact;
use r#type::RedactScalar;
use r#type::Redactor;

#[derive(RedactScalar)]
struct AutomaticToken(String);

#[derive(Redact)]
struct AutomaticRecord {
    #[redact(level = "secret")]
    token: AutomaticToken,
}

#[derive(RedactScalar)]
#[redact(crate = r#type)]
struct ExplicitToken(String);

#[derive(Redact)]
#[redact(crate = r#type)]
struct ExplicitRecord {
    #[redact(level = "secret")]
    token: ExplicitToken,
}

fn main() {
    let redactor = Redactor::standard();
    let automatic = AutomaticRecord {
        token: AutomaticToken("automatic-raw-secret".to_owned()),
    };
    let explicit = ExplicitRecord {
        token: ExplicitToken("explicit-raw-secret".to_owned()),
    };
    let automatic = redactor.redact_text(&automatic);
    let explicit = redactor.redact_text(&explicit);
    assert!(automatic.complete_text().is_ok());
    assert!(automatic.text().as_str().contains("<redacted>"));
    assert!(!automatic.text().as_str().contains("automatic-raw-secret"));
    assert!(explicit.complete_text().is_ok());
    assert!(explicit.text().as_str().contains("<redacted>"));
    assert!(!explicit.text().as_str().contains("explicit-raw-secret"));
}
