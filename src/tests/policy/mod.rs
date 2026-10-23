// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal policy contracts unavailable through published field metadata.

mod masking;
mod redaction_policy_tests;
#[cfg(feature = "http")]
mod resolved_field_tests;
