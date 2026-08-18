// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Log-safe formatting for domain debug views.

use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Write as _;

use crate::output::internal::BoundedLogEscapeWriter;

pub(crate) fn format_log_safe(value: &dyn Debug, formatter: &mut Formatter<'_>) -> fmt::Result {
    let mut writer = BoundedLogEscapeWriter::new(usize::MAX);
    write!(&mut writer, "{value:?}")?;
    formatter.write_str(&writer.finish())
}
