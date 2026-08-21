// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Process-command redaction built on the active redaction transaction.

mod admitted_command_items;
mod admitted_environment_pairs;
mod command_items;
mod process_redaction_writer;

pub use process_redaction_writer::ProcessRedactionWriter;
