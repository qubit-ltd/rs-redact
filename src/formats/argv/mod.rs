// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redaction adapters for process argument vectors.

mod argv_item;
mod argv_redaction_writer;
pub(crate) mod batch_redaction;
pub(crate) mod inspection;
mod pending_field;
pub(crate) mod redaction;

pub use argv_item::ArgvItem;
pub use argv_redaction_writer::ArgvRedactionWriter;
