//! Tests for [`RedactMapValue`](qubit_redact::RedactMapValue).

use std::collections::BTreeMap;

use qubit_redact::{
    RedactedMap,
    RedactionPolicy,
};

/// Verifies map formatting classifies values using their runtime keys.
#[test]
fn test_redact_map_value_masks_sensitive_map_entry() {
    let map = BTreeMap::from([(String::from("password"), String::from("raw"))]);
    let rendered =
        RedactedMap::new(&map, RedactionPolicy::default()).to_string();

    assert!(!rendered.contains("raw"));
    assert!(rendered.contains("<redacted>"));
}
