// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Scoped ownership markers for logical Serde scalar payloads.

mod serde_payload_event_guard;
mod serde_payload_forward_guard;

pub(super) use serde_payload_event_guard::SerdePayloadEventGuard;
pub(super) use serde_payload_forward_guard::SerdePayloadForwardGuard;

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    use serde::Serialize;
    use serde_json::Serializer as JsonSerializer;
    use serde_json::ser::Formatter;

    use super::super::budget_serializer::BudgetSerializer;
    use super::super::redact_serialize_scope::RedactSerializeScope;
    use super::super::redact_serialize_scope::serialize_payload;
    use crate::RedactionPolicy;
    use crate::domain::internal::BudgetSerialize;

    struct ReentrantFormatter {
        did_reenter: bool,
        nested_rejected: Arc<AtomicBool>,
    }

    impl Formatter for ReentrantFormatter {
        fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
        where
            W: ?Sized + Write,
        {
            if !self.did_reenter {
                self.did_reenter = true;
                let mut nested_output = Vec::new();
                let mut nested_serializer = JsonSerializer::new(&mut nested_output);
                let nested_result = BudgetSerialize::new("x").serialize(&mut nested_serializer);
                self.nested_rejected.store(nested_result.is_err(), Ordering::SeqCst);
            }
            writer.write_all(fragment.as_bytes())
        }
    }

    #[test]
    fn test_downstream_serializer_reentry_does_not_reuse_forwarding_credit() {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_serde_payload_bytes(3);
            })
            .expect("valid limits")
            .build()
            .expect("valid policy");
        let _scope = RedactSerializeScope::new(&policy);
        let nested_rejected = Arc::new(AtomicBool::new(false));
        let formatter = ReentrantFormatter {
            did_reenter: false,
            nested_rejected: Arc::clone(&nested_rejected),
        };
        let mut output = Vec::new();
        let mut serializer = JsonSerializer::with_formatter(&mut output, formatter);

        serialize_payload(BudgetSerializer { inner: &mut serializer }, "abc")
            .expect("the already admitted outer payload should serialize");

        assert!(
            nested_rejected.load(Ordering::SeqCst),
            "a reentrant payload must consume its own budget allowance"
        );
        assert_eq!(output, br#""abc""#);
    }
}
