// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::Redact as RedactTrait;
use qubit_redact::RedactionWriter;
use qubit_redact_derive::Redact;

struct Child;

impl RedactTrait for Child {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("Child");
    }
}

#[derive(Redact)]
#[redact(serde)]
struct Bad {
    #[redact(nested)]
    child: Child,
}

fn main() {
    // Text-only children remain derivable, but requesting Serde must fail.
    let _ = serde_json::to_value(Bad { child: Child });
}
// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
