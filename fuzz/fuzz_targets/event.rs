// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Composite payload for nested, map, and JSON projection fuzzing.

use std::collections::BTreeMap;

use qubit_redact::Redact;
use serde_json::Value;

use super::Login;

/// Exercises nested, map, and JSON projections within the same payload.
#[derive(Redact)]
#[redact(serde)]
pub(super) struct Event {
    /// Nested record whose field annotations determine masking.
    #[redact(nested)]
    pub(super) login: Login,
    /// Map payload used to exercise key-based masking.
    #[redact(map)]
    pub(super) attributes: BTreeMap<String, String>,
    /// JSON payload used to exercise structured masking.
    #[redact(json)]
    pub(super) body: Value,
}
