// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Forwards borrowed projection capability through existing pointer wrappers.

use std::rc::Rc;
use std::sync::Arc;

use super::redact_serialize_source::RedactSerializeSource;
use crate::RedactionPolicy;

impl<T: RedactSerializeSource + ?Sized> RedactSerializeSource for &T {
    type RedactedFields<'a>
        = T::RedactedFields<'a>
    where
        Self: 'a;

    fn redacted_fields<'a>(&'a self, policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
        (**self).redacted_fields(policy)
    }
}

macro_rules! pointer_projection_forwarding {
    ($pointer:ident) => {
        impl<T: RedactSerializeSource + ?Sized> RedactSerializeSource for $pointer<T> {
            type RedactedFields<'a>
                = T::RedactedFields<'a>
            where
                Self: 'a;

            fn redacted_fields<'a>(&'a self, policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
                (**self).redacted_fields(policy)
            }
        }
    };
}

pointer_projection_forwarding!(Box);
pointer_projection_forwarding!(Rc);
pointer_projection_forwarding!(Arc);
