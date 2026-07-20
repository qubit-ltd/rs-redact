// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Container implementations for explicit nested redaction.

use std::fmt::{
    self,
    Formatter,
};

use crate::{
    Redact,
    RedactionPolicy,
};

impl<T: Redact> Redact for Option<T> {
    /// Formats `None` directly or a redacted `Some` value with the same policy.
    #[inline]
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        match self {
            Some(value) => formatter
                .debug_tuple("Some")
                .field(&value.redacted_with(policy))
                .finish(),
            None => formatter.write_str("None"),
        }
    }
}

impl<T: Redact + ?Sized> Redact for Box<T> {
    /// Transparently delegates formatting to the boxed object.
    #[inline(always)]
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        self.as_ref().fmt_redacted(policy, formatter)
    }
}

impl<T: Redact> Redact for Vec<T> {
    /// Formats every item through a redacted view sharing the same policy.
    #[inline]
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        let mut list = formatter.debug_list();
        for value in self {
            list.entry(&value.redacted_with(policy));
        }
        list.finish()
    }
}
