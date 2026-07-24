// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal streaming writers for log-safe text.

mod bounded_log_escape_writer;
mod log_escape_writer;

pub(crate) use bounded_log_escape_writer::BoundedLogEscapeWriter;
pub(crate) use log_escape_writer::LogEscapeWriter;
