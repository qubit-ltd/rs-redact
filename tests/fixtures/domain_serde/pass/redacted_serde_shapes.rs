// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Passing fixture for all redacted Serde container shapes.

use qubit_redact::Redact;
use qubit_redact_derive::Redact;

/// Serializable tuple struct.
#[derive(Redact)]
#[redact(serde)]
struct Tuple(
    #[redact(level = "secret")] String,
    #[redact(skip)] String,
);

/// Serializable unit struct.
#[derive(Redact)]
#[redact(serde)]
struct Unit;

/// Externally tagged enum.
#[derive(Redact)]
#[redact(serde)]
enum External {
    /// Named variant.
    Named {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple variant.
    Tuple(#[redact(level = "secret")] String),
    /// Unit variant.
    Unit,
}

/// Internally tagged enum with valid content.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum Internal {
    /// Named variant.
    Named {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Unit variant.
    Unit,
}

/// Adjacently tagged enum.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "payload")]
enum Adjacent {
    /// Tuple variant.
    Tuple(#[redact(level = "secret")] String, String),
    /// Unit variant.
    Unit,
}

/// Untagged enum.
#[derive(Redact)]
#[redact(serde)]
#[serde(untagged)]
enum Untagged {
    /// Named variant.
    Named {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple variant.
    Tuple(#[redact(level = "secret")] String, String),
    /// Unit variant.
    Unit,
}

/// Serializes representative redacted values.
fn main() {
    let _ = serde_json::to_string(&Tuple(String::new(), String::new()).redacted());
    let _ = serde_json::to_string(&Unit.redacted());
    let _ = serde_json::to_string(
        &External::Named {
            secret: String::new(),
        }
        .redacted(),
    );
    let _ = serde_json::to_string(
        &Internal::Named {
            secret: String::new(),
        }
        .redacted(),
    );
    let _ = serde_json::to_string(
        &Adjacent::Tuple(String::new(), String::new()).redacted(),
    );
    let _ = serde_json::to_string(
        &Untagged::Named {
            secret: String::new(),
        }
        .redacted(),
    );
}
