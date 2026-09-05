//! Explicit third-party Display adaptation is lazy and policy-aware.
#![cfg(feature = "derive")]

use std::cell::Cell;
use std::fmt;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

struct External<'a> {
    calls: &'a Cell<usize>,
}

impl fmt::Display for External<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.calls.set(self.calls.get() + 1);
        f.write_str("abcdef")
    }
}

#[derive(Redact)]
#[cfg_attr(feature = "serde", redact(serialize))]
struct Secret<T> {
    #[redact(level = "secret", display)]
    value: T,
}

#[derive(Redact)]
#[cfg_attr(feature = "serde", redact(serialize))]
struct Low<T> {
    #[redact(display, level = "low")]
    value: T,
}

#[test]
fn test_display_is_not_called_for_opaque_masks() {
    let calls = Cell::new(0);
    let value = Secret {
        value: External { calls: &calls },
    };
    assert!(
        Redactor::standard()
            .redact_text(&value)
            .text()
            .as_str()
            .contains("<redacted>")
    );
    assert_eq!(calls.get(), 0);
    #[cfg(all(feature = "serde", feature = "json"))]
    {
        assert_eq!(
            Redactor::standard().to_json(&value).expect("opaque JSON"),
            r#"{"value":"<redacted>"}"#
        );
        assert_eq!(calls.get(), 0);
    }
    let disabled = Redactor::new(RedactionPolicy::disabled());
    assert!(disabled.redact_text(&value).text().as_str().contains("abcdef"));
    assert_eq!(calls.get(), 1);
    #[cfg(all(feature = "serde", feature = "json"))]
    {
        assert_eq!(
            disabled.to_json(&value).expect("Display string JSON"),
            r#"{"value":"abcdef"}"#
        );
        assert_eq!(calls.get(), 2);
    }
}

#[test]
fn test_display_low_level_is_final_even_under_strict_policy() {
    let calls = Cell::new(0);
    let value = Low {
        value: External { calls: &calls },
    };
    assert!(
        Redactor::strict()
            .redact_text(&value)
            .text()
            .as_str()
            .contains("ab****ef")
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn test_display_respects_input_budget_without_unbounded_capture() {
    let calls = Cell::new(0);
    let value = Low {
        value: External { calls: &calls },
    };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);
    let output = redactor.redact_text(&value);
    assert!(!output.text().as_str().contains("abcdef"));
    #[cfg(all(feature = "serde", feature = "json"))]
    {
        let json = redactor.to_json(&value).expect("bounded replacement");
        assert_eq!(json, r#"{"value":"<redacted>"}"#);
    }
}
