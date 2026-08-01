// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for lazy key-sensitive map redaction.

use std::{
    cell::Cell,
    collections::{
        BTreeMap,
        HashMap,
        hash_map,
    },
};

use qubit_redact::{
    Redact,
    RedactedMap,
    RedactionPolicy,
    Sensitivity,
};
use qubit_redact_derive::Redact;

/// Event containing marked and unmarked maps.
#[derive(Redact)]
struct Event {
    /// Values classified by their runtime keys.
    #[redact(map)]
    metadata: HashMap<String, String>,
    /// Control map that remains ordinary debug output.
    unmarked: BTreeMap<String, String>,
}

/// Custom map recording borrowed iteration.
struct CountingMap {
    /// Wrapped map entries.
    entries: HashMap<String, String>,
    /// Number of times borrowed iteration began.
    traversals: Cell<usize>,
}

impl<'a> IntoIterator for &'a CountingMap {
    type Item = (&'a String, &'a String);
    type IntoIter = hash_map::Iter<'a, String, String>;

    /// Records and starts one borrowed traversal.
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.traversals.set(self.traversals.get() + 1);
        self.entries.iter()
    }
}

/// Holder proving map view creation is lazy.
#[derive(Redact)]
struct CountedEvent {
    /// Instrumented map.
    #[redact(map)]
    metadata: CountingMap,
}

/// Verifies marked maps use the view policy without changing their source.
#[test]
fn test_map_uses_view_policy_lazily_and_unmarked_map_stays_plain() {
    let policy = RedactionPolicy::empty_builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .build()
        .expect("the field rule is valid");
    let event = Event {
        metadata: HashMap::from([
            ("tenant_secret".to_owned(), "raw-map-secret".to_owned()),
            ("label".to_owned(), "visible".to_owned()),
        ]),
        unmarked: BTreeMap::from([(
            "tenant_secret".to_owned(),
            "raw-unmarked".to_owned(),
        )]),
    };

    let rendered = format!("{:?}", event.redacted_with(&policy));

    assert!(!rendered.contains("raw-map-secret"));
    assert!(rendered.contains("visible"));
    assert!(rendered.contains("raw-unmarked"));
    assert_eq!(event.metadata["tenant_secret"], "raw-map-secret");
}

/// Verifies a map is traversed only when its redacted view is formatted.
#[test]
fn test_map_view_defers_iteration_until_debug_formatting() {
    let event = CountedEvent {
        metadata: CountingMap {
            entries: HashMap::from([(
                "label".to_owned(),
                "visible".to_owned(),
            )]),
            traversals: Cell::new(0),
        },
    };

    let view = event.redacted();
    assert_eq!(event.metadata.traversals.get(), 0);

    let _ = format!("{view:?}");
    assert_eq!(event.metadata.traversals.get(), 1);
}

/// Verifies plain-text map output escapes log-control characters.
#[test]
fn test_map_display_is_log_safe() {
    let event = Event {
        metadata: HashMap::from([(
            "label".to_owned(),
            "first\nsecond".to_owned(),
        )]),
        unmarked: BTreeMap::new(),
    };

    let rendered =
        RedactedMap::new(&event.metadata, RedactionPolicy::default())
            .to_string();

    assert!(!rendered.contains('\n'));
    assert!(rendered.contains(r"first\nsecond"));
}
