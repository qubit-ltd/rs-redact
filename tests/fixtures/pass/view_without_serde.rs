// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use qubit_redact::Redactor;
use qubit_redact_derive::Redact as DeriveRedact;

#[derive(DeriveRedact)]
struct Plain {
    value: String,
}

fn main() {
    let value = Plain {
        value: "visible".to_owned(),
    };
    let _ = serde_json::to_string(&Redactor::standard().redact_view(&value));
}
