// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Process, argument-vector, and environment redaction operations.

use std::ffi::OsStr;

use super::Redactor;
use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionTextOutput;

impl Redactor {
    /// Redacts an argument vector through one completed text transaction.
    #[must_use]
    pub fn redact_argv<'items, I>(&self, items: I) -> RedactionTextOutput
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        let mut session = self.text_runtime();
        session.argv(|argv| {
            let _ = argv.items(items);
        });
        session.finish()
    }

    /// Inspects explicitly classified argv items without rendering them.
    pub fn inspect_argv<'items, I>(&self, items: I) -> Result<RedactionInspection, RedactionInspectionError>
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        let mut session = self.inspection_runtime();
        crate::formats::argv::inspection::inspect_items(&mut session, items, false);
        session.finish()
    }

    /// Redacts argv items using heuristic option classification.
    #[must_use]
    pub fn redact_heuristic_argv<'items, I>(&self, items: I) -> RedactionTextOutput
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        let mut session = self.text_runtime();
        session.argv(|argv| {
            let _ = argv.heuristic_items(items);
        });
        session.finish()
    }

    /// Inspects argv items using heuristic option classification.
    pub fn inspect_heuristic_argv<'items, I>(&self, items: I) -> Result<RedactionInspection, RedactionInspectionError>
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        let mut session = self.inspection_runtime();
        crate::formats::argv::inspection::inspect_items(&mut session, items, true);
        session.finish()
    }

    /// Redacts one environment assignment through one completed transaction.
    #[must_use]
    pub fn redact_env(&self, name: &str, value: &str) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.env(|environment| {
            let _ = environment.pair(name, value);
        });
        session.finish()
    }

    /// Inspects one environment assignment without rendering it.
    pub fn inspect_env(&self, name: &str, value: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        crate::formats::env::inspection::inspect_pair(&mut session, name, value);
        session.finish()
    }

    /// Redacts environment assignments through one completed transaction.
    #[must_use]
    pub fn redact_env_pairs<'items, I>(&self, pairs: I) -> RedactionTextOutput
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        let mut session = self.text_runtime();
        session.env(|environment| {
            let _ = environment.os_pairs(pairs);
        });
        session.finish()
    }

    /// Inspects environment assignments without rendering them.
    pub fn inspect_env_pairs<'items, I>(&self, pairs: I) -> Result<RedactionInspection, RedactionInspectionError>
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        let mut session = self.inspection_runtime();
        crate::formats::env::inspection::inspect_os_pairs(&mut session, pairs);
        session.finish()
    }

    /// Redacts one process command through one completed text transaction.
    #[must_use]
    pub fn redact_process<'arguments, 'variables, A, E>(
        &self,
        program: &'arguments OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionTextOutput
    where
        A: IntoIterator<Item = crate::formats::argv::ArgvItem<'arguments>>,
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
    {
        let mut session = self.text_runtime();
        let _ = session.process(|process| {
            let _ = process.command(program, arguments, variables);
        });
        session.finish()
    }

    /// Inspects one process command without rendering its components.
    pub fn inspect_process<'arguments, 'variables, A, E>(
        &self,
        program: &'arguments OsStr,
        arguments: A,
        variables: E,
    ) -> Result<RedactionInspection, RedactionInspectionError>
    where
        A: IntoIterator<Item = crate::formats::argv::ArgvItem<'arguments>>,
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
    {
        let mut session = self.inspection_runtime();
        let command = std::iter::once(crate::formats::argv::ArgvItem::plain(program)).chain(arguments);
        crate::formats::argv::inspection::inspect_items(&mut session, command, true);
        crate::formats::env::inspection::inspect_os_pairs(&mut session, variables);
        session.finish()
    }
}
