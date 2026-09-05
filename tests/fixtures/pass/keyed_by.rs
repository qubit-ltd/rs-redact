// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde, debug, display)]
struct Pair {
    key: String,
    #[redact(keyed_by = key)]
    value: Option<String>,
}

fn main() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("password");
        })
        .expect("field policy")
        .build()
        .expect("policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));
    let pair = Pair {
        key: "password".to_owned(),
        value: Some("raw-secret".to_owned()),
    };

    assert!(!format!("{pair:?}").contains("raw-secret"));
    assert!(!serde_json::to_string(&pair).expect("serialize").contains("raw-secret"));

    let _ = Redactor::replace_application_default(previous);
}
// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
