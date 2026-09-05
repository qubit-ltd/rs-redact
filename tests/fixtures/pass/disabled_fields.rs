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
struct Record {
    #[redact(level = "secret")]
    number: u32,
    #[redact(skip)]
    restored_when_disabled: String,
}

fn main() {
    let _ = Record {
        number: 7,
        restored_when_disabled: "raw".to_owned(),
    };
}
// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
