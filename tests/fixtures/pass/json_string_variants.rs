// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use std::borrow::Cow;

use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct JsonStrings<'a> {
    #[redact(json)]
    owned: String,
    #[redact(json)]
    borrowed: &'a str,
    #[redact(json)]
    cow: Cow<'a, str>,
    #[redact(json)]
    optional: Option<Cow<'a, str>>,
}

fn main() {
    let _ = JsonStrings {
        owned: "{}".to_owned(),
        borrowed: "{}",
        cow: Cow::Borrowed("{}"),
        optional: None,
    };
}
// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
