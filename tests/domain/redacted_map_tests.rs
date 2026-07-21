//! Tests for [`RedactedMap`](qubit_redact::RedactedMap).

use std::collections::BTreeMap;

use qubit_redact::{
    RedactedMap,
    RedactionPolicy,
};

/// Verifies a redacted map keeps non-sensitive values visible.
#[test]
fn test_redacted_map_preserves_visible_value() {
    let map =
        BTreeMap::from([(String::from("label"), String::from("visible"))]);
    let rendered =
        RedactedMap::new(&map, RedactionPolicy::default()).to_string();

    assert!(rendered.contains("visible"));
}
