//! Tests for [`Sensitivity`](qubit_redact::Sensitivity).

use qubit_redact::Sensitivity;

/// Verifies sensitivity ordering increases with secrecy.
#[test]
fn test_sensitivity_orders_from_low_to_secret() {
    assert!(Sensitivity::Low < Sensitivity::Medium);
    assert!(Sensitivity::Medium < Sensitivity::High);
    assert!(Sensitivity::High < Sensitivity::Secret);
}
