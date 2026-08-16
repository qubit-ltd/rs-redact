// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Hidden exports consumed only by generated derive code.

/// Runtime implementation details used by `qubit-redact-derive`
/// expansions.
pub use crate::domain::RedactMapSerialize;
pub use crate::domain::RedactSerialize;
pub use crate::domain::internal::RedactedSerialize;
pub use crate::domain::internal::serialize_internally_tagged;
