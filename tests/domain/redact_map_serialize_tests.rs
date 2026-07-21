//! Tests for serde redaction of map values.

#[cfg(feature = "serde")]
use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use qubit_redact::{
    RedactedMap,
    RedactionPolicy,
};

/// Verifies map serialization masks values classified from their keys.
#[cfg(feature = "serde")]
#[test]
fn test_redact_map_serialize_masks_sensitive_value() {
    let map = BTreeMap::from([(String::from("password"), String::from("raw"))]);
    let serialized = serde_json::to_string(&RedactedMap::new(
        &map,
        RedactionPolicy::default(),
    ))
    .expect("redacted map serialization should succeed");

    assert!(!serialized.contains("raw"));
}
