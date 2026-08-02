// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redaction adapters for process argument vectors.

mod argv_item;
mod argv_redactor;
mod pending_field;
mod redacted_argv;
mod redacted_argv_builder;

pub use argv_item::ArgvItem;
pub use argv_redactor::ArgvRedactor;
pub use redacted_argv::RedactedArgv;
