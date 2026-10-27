// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::Redact;

#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum Event {
    Named {
        #[serde(skip)]
        ignored: u8,
        #[serde(rename = "kind")]
        value: String,
    },
}

fn main() {}
