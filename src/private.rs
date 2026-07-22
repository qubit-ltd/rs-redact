// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Hidden exports consumed only by generated derive code.

/// Runtime implementation details used by `qubit-redact-derive` expansions.
#[doc(hidden)]
pub mod __private {
    pub use crate::domain::internal::RedactedSerialize;
    pub use crate::domain::{
        RedactMapSerialize,
        RedactSerialize,
    };
}
