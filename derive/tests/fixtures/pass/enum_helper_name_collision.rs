// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for enum helper contexts with colliding textual names.

#![allow(non_camel_case_types)]

use qubit_redact::{Redact as RedactTrait, RedactMut as RedactMutTrait};
use qubit_redact_derive::{Redact, RedactMut};

/// Enum variants whose old helper contexts both became `foo_bar_baz`.
#[derive(Redact, RedactMut)]
enum Collision {
    /// Variant whose name contributes the first half of the collision.
    foo_bar {
        /// Sensitive value.
        #[redact(level = "secret")]
        baz: String,
    },
    /// Variant whose field contributes the second half of the collision.
    foo {
        /// Sensitive value.
        #[redact(level = "secret")]
        bar_baz: String,
    },
}

/// Exercises both immutable and mutable generated helpers.
fn main() {
    let first = Collision::foo_bar {
        baz: "first-secret".to_owned(),
    };
    let second = Collision::foo {
        bar_baz: "second-secret".to_owned(),
    };
    assert!(!format!("{:?}", first.redacted()).contains("first-secret"));
    assert!(!format!("{:?}", second.redacted()).contains("second-secret"));

    let mut first = first;
    let mut second = second;
    first.redact_in_place();
    second.redact_in_place();
}
