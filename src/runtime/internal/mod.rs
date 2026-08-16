// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime-only completion and admission states.

mod fragment_completion;
mod redaction_admission;

pub(crate) use fragment_completion::FragmentCompletion;
pub(crate) use redaction_admission::RedactionAdmission;
