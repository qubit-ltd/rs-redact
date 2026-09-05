// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct Child {
    #[redact(level = "secret")]
    token: String,
}

#[derive(Redact)]
#[redact(serde)]
struct Parent {
    #[redact(nested)]
    children: Option<Vec<Child>>,
}

fn main() {
    let value = Parent {
        children: Some(vec![Child { token: "raw".to_owned() }]),
    };
    let _ = serde_json::to_value(value).unwrap();
}
// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
