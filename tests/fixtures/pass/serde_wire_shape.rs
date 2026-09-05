// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct Response {
    name: String,
    #[redact(level = "secret")]
    token: String,
}

fn main() {
    let value = Response { name: "Ada".into(), token: "raw".into() };
    let encoded = serde_json::to_value(&value).expect("serialize");
    assert_eq!(encoded["name"], "Ada");
    assert_ne!(encoded["token"], "raw");
    let _ = Redactor::standard().redact(&value);
}
// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
