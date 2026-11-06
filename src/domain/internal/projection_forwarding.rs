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
    /// The pointee's projection, retaining only the source borrow.
    ///
    /// # Type Parameters
    ///
    /// - `'a`: Lifetime of the borrowed source retained by the projection.
    type RedactedFields<'a>
        = T::RedactedFields<'a>
    where
        Self: 'a;

    /// Borrows the pointee's fields without cloning or moving the source.
    ///
    /// # Type Parameters
    ///
    /// - `'a`: Lifetime of the source borrow retained by the projection.
    ///
    /// # Parameters
    ///
    /// - `policy`: Policy forwarded unchanged; it is not retained by the
    ///   projection.
    ///
    /// # Returns
    ///
    /// The pointee's borrowed projection, unchanged by this wrapper.
    #[inline]
    fn redacted_fields<'a>(&'a self, policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
        (**self).redacted_fields(policy)
    }
}

/// Implements borrowed projection forwarding without cloning the owning
/// pointer.
macro_rules! pointer_projection_forwarding {
    ($pointer:ident) => {
        impl<T: RedactSerializeSource + ?Sized> RedactSerializeSource for $pointer<T> {
            /// The pointee's projection, borrowing the source through this pointer.
            ///
            /// # Type Parameters
            ///
            /// - `'a`: Lifetime of the source borrow retained by the projection.
            type RedactedFields<'a>
                = T::RedactedFields<'a>
            where
                Self: 'a;

            /// Borrows the pointee's fields without cloning the pointer or source.
            ///
            /// # Type Parameters
            ///
            /// - `'a`: Lifetime of the source borrow retained by the projection.
            ///
            /// # Parameters
            ///
            /// - `policy`: Policy forwarded unchanged and not retained by the
            ///   projection.
            ///
            /// # Returns
            ///
            /// The pointee's borrowed projection without changing pointer ownership.
            #[inline]
            fn redacted_fields<'a>(&'a self, policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
                (**self).redacted_fields(policy)
            }
        }
    };
}

pointer_projection_forwarding!(Box);
pointer_projection_forwarding!(Rc);
pointer_projection_forwarding!(Arc);
