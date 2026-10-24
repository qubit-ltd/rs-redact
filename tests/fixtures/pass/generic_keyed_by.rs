// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Debug, Redact)]
#[redact(serde)]
struct Pair<K, V> {
    key: K,
    #[redact(keyed_by = key)]
    value: V,
}

fn main() {
    let pair = Pair {
        key: String::from("credential"),
        value: String::from("secret"),
    };
    let redactor = Redactor::standard();
    let _ = redactor.redact_text(&pair);
    let _ = serde_json::to_value(redactor.redact_view(&pair));
    let _ = serde_json::to_value(&pair);
}
