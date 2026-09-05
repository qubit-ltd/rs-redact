// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for generated safe `Debug` and `Display` implementations.

use std::fmt;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

/// Marker that intentionally implements no formatting trait.
#[derive(Debug)]
struct NoFormatting;

/// Record using both generated formatting implementations.
#[derive(Redact)]
#[redact(debug, display)]
struct Credentials {
    /// Visible field rendered through ordinary `Debug`.
    visible: &'static str,
    /// Secret field rendered through the configured mask.
    #[redact(level = "secret")]
    password: String,
    /// Omitted field that imposes no formatting bound.
    #[redact(skip)]
    ignored: NoFormatting,
}

/// Record proving `display` does not require the original type to implement
/// `Debug` separately.
#[derive(Redact)]
#[redact(display)]
struct DisplayOnly {
    /// Secret value.
    #[redact(level = "secret")]
    secret: String,
}

/// Debug value that must remain untouched after admission is rejected.
struct PanicDebug;

impl fmt::Debug for PanicDebug {
    /// Panics if generated code formats an unadmitted field.
    fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("an unadmitted field must not be formatted");
    }
}

/// Record that reaches its node ceiling before the second field.
#[derive(Redact)]
struct Guarded {
    /// Field admitted after the root value.
    visible: &'static str,
    /// Field rejected before its debug implementation can run.
    blocked: PanicDebug,
}

/// Exercises every generated trait implementation.
fn main() {
    let value = Credentials {
        visible: "visible",
        password: "raw-password".to_owned(),
        ignored: NoFormatting,
    };
    let _ = &value.ignored;
    assert_eq!(
        format!("{value:?}"),
        r#"Credentials { visible: "visible", password: "<redacted>" }"#,
    );
    let _ = format!("{value:#?}");
    assert_eq!(
        format!("{value}"),
        r#"Credentials { visible: "visible", password: "<redacted>" }"#,
    );

    let display_only = DisplayOnly {
        secret: "raw-secret".to_owned(),
    };
    assert_eq!(
        format!("{display_only}"),
        r#"DisplayOnly { secret: "<redacted>" }"#,
    );

    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(2).max_collection_items(1).max_depth(1);
        })
        .expect("the fixture redaction policy limits should be valid")
        .build()
        .expect("the fixture redaction policy should be valid");
    let guarded = Guarded {
        visible: "visible",
        blocked: PanicDebug,
    };
    assert!(
        !Redactor::new(policy)
            .redact(&guarded)
            .text()
            .as_str()
            .contains("PanicDebug")
    );
}
