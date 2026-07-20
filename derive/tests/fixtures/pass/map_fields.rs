// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for string-valued map fields.

use std::collections::{BTreeMap, HashMap};

use qubit_redact::Redact as RedactTrait;
use qubit_redact_derive::Redact;

/// Supported standard map types.
#[derive(Redact)]
struct Maps {
    /// Hash map redacted by runtime keys.
    #[redact(map)]
    hash: HashMap<String, String>,
    /// Ordered map redacted by runtime keys.
    #[redact(map)]
    tree: BTreeMap<String, String>,
}

/// Formats both supported maps.
fn main() {
    let maps = Maps {
        hash: HashMap::new(),
        tree: BTreeMap::new(),
    };
    let _ = format!("{:?}", maps.redacted());
}
