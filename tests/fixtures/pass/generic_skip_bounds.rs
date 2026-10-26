// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Generic skipped fields retain their conditional `Debug` requirement.

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Named<T> {
    #[redact(skip)]
    cache: T,
}

#[derive(Redact)]
struct Tuple<T>(#[redact(skip)] T);

#[derive(Redact)]
enum Choice<T> {
    Named { #[redact(skip)] cache: T },
    Tuple(#[redact(skip)] T),
}

fn main() {
    let named = Named { cache: "named-hidden" };
    let tuple = Tuple("tuple-hidden");
    let choice_named = Choice::Named { cache: "enum-named-hidden" };
    let choice_tuple = Choice::Tuple("enum-tuple-hidden");
    let standard = Redactor::standard();
    assert!(!standard.redact_text(&named).text().as_str().contains("named-hidden"));
    assert!(!standard.redact_text(&tuple).text().as_str().contains("tuple-hidden"));
    assert!(!standard.redact_text(&choice_named).text().as_str().contains("enum-named-hidden"));
    assert!(!standard.redact_text(&choice_tuple).text().as_str().contains("enum-tuple-hidden"));
    let disabled = Redactor::new(RedactionPolicy::disabled());
    assert!(disabled.redact_text(&named).text().as_str().contains("named-hidden"));
    assert!(disabled.redact_text(&tuple).text().as_str().contains("tuple-hidden"));
    assert!(disabled.redact_text(&choice_named).text().as_str().contains("enum-named-hidden"));
    assert!(disabled.redact_text(&choice_tuple).text().as_str().contains("enum-tuple-hidden"));
}
