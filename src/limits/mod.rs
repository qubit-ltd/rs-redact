// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Cross-format input, output, and traversal limits.

pub use crate::policy::DiagnosticBudgetError;
pub use crate::policy::DomainRedactionLimits;
pub use crate::policy::DomainRedactionLimitsBuilder;
pub use crate::policy::DomainRedactionLimitsError;
pub use crate::policy::InputOutputLimit;
pub use crate::policy::InputOutputLimitBuilder;
#[cfg(feature = "json")]
pub use crate::policy::JsonDepthLimit;
#[cfg(feature = "json")]
pub use crate::policy::JsonDepthLimitBuilder;
#[cfg(feature = "json")]
pub use crate::policy::JsonDepthLimitError;
pub use crate::policy::RedactionLimits;
pub use crate::policy::RedactionLimitsBuilder;
