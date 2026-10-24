// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================

use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Debug, Redact)]
struct Child {
    value: NotSerializable,
}

#[derive(Redact)]
struct Parent {
    #[redact(nested)]
    child: Child,
}

#[derive(Debug)]
struct NotSerializable;

fn main() {
    let parent = Parent { child: Child { value: NotSerializable } };
    let _ = Redactor::standard().to_json(&parent);
}
