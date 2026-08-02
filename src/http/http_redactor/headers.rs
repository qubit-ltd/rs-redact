// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Deterministic grouping for HTTP header rendering.

use std::collections::BTreeMap;

use http::{
    HeaderMap,
    HeaderValue,
};

/// Groups repeated header values under deterministically ordered names.
pub(super) fn group_values(
    headers: &HeaderMap,
) -> BTreeMap<&str, Vec<&HeaderValue>> {
    let mut values = BTreeMap::<&str, Vec<&HeaderValue>>::new();
    for (name, value) in headers {
        values.entry(name.as_str()).or_default().push(value);
    }
    values
}
