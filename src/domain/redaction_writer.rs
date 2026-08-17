// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Restricted structured writer used by domain redaction implementations.
// qubit-style: allow multiple-public-types

use std::fmt::Debug;

use crate::RedactionPolicy;
use crate::Sensitivity;

/// Restricted writer for one redaction operation.
///
/// The constructor is crate-private. User implementations can only emit
/// through structured methods, so the raw output buffer and policy snapshot
/// cannot be replaced or bypassed.
pub struct RedactionWriter<'session> {
    output: &'session mut String,
    policy: &'session RedactionPolicy,
}

impl<'session> RedactionWriter<'session> {
    /// Creates a writer for an internal redaction operation.
    #[must_use]
    pub(crate) fn new(
        output: &'session mut String,
        policy: &'session RedactionPolicy,
    ) -> Self {
        Self { output, policy }
    }

    /// Writes a trusted static structural literal.
    #[inline]
    pub fn literal(&mut self, text: &'static str) {
        self.output.push_str(text);
    }

    /// Writes a named record through a field scope.
    pub fn record<F>(&mut self, name: &str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.output.push_str(name);
        self.output.push_str(" { ");
        let mut fields = RedactionFields { writer: self };
        configure(&mut fields);
        fields.writer.output.push_str(" }");
    }

    /// Uses the previous formatter-based implementation as a safe bridge.
    pub(crate) fn legacy<T>(&mut self, value: &T)
    where
        T: super::Redact,
    {
        let rendered = format!("{:?}", value.redacted_with(self.policy));
        self.output.push_str(&rendered);
    }

    /// Returns the policy snapshot used by this writer.
    #[must_use]
    pub(crate) const fn policy(&self) -> &RedactionPolicy {
        self.policy
    }
}

/// Field scope for a record writer.
pub struct RedactionFields<'writer, 'session> {
    writer: &'writer mut RedactionWriter<'session>,
}

impl RedactionFields<'_, '_> {
    /// Writes a field classified by the runtime field policy.
    #[must_use]
    pub fn field<T, F>(&mut self, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        let raw = format!("{:?}", access());
        let redacted = crate::Redactor::new(self.writer.policy().clone())
            .redact_field(name, &raw);
        self.writer.output.push_str(name);
        self.writer.output.push_str(": ");
        self.writer.output.push_str(redacted.as_str());
        self.writer.output.push_str(", ");
        self
    }

    /// Writes a field with an explicit minimum sensitivity.
    #[must_use]
    pub fn sensitive<T, F>(
        &mut self,
        level: Sensitivity,
        name: &str,
        access: F,
    ) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        let value = if matches!(level, Sensitivity::High | Sensitivity::Secret)
        {
            self.writer.policy().masking().mask_opaque(level).to_owned()
        } else {
            let raw = format!("{:?}", access());
            crate::Redactor::new(self.writer.policy().clone())
                .redact_at(level, &raw)
                .into_owned()
        };
        self.writer.output.push_str(name);
        self.writer.output.push_str(": ");
        self.writer.output.push_str(&value);
        self.writer.output.push_str(", ");
        self
    }
}
