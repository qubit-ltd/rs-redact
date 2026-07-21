//! Tests for serde support on redacted domain views.

/// Asserts at compile time that a type implements [`serde::Serialize`].
#[cfg(feature = "serde")]
fn assert_serialize<T: serde::Serialize>() {}

/// Verifies redacted map views implement serde serialization.
#[cfg(feature = "serde")]
#[test]
fn test_redacted_serialize_redacted_map_implements_serialize() {
    assert_serialize::<
        qubit_redact::RedactedMap<
            'static,
            std::collections::BTreeMap<String, String>,
        >,
    >();
}
