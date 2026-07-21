//! Tests for [`RedactMapValueMut`](qubit_redact::RedactMapValueMut).

use std::collections::BTreeMap;

use qubit_redact::{
    RedactMapValueMut,
    RedactionPolicy,
};

/// Verifies in-place map redaction replaces only sensitive values.
#[test]
fn test_redact_map_value_mut_replaces_sensitive_value() {
    let mut map =
        BTreeMap::from([(String::from("password"), String::from("raw"))]);
    map.redact_map_in_place(&RedactionPolicy::default());

    assert_eq!(map["password"], "<redacted>");
}
