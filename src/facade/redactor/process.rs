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
use crate::RedactionInspectionResult;
use crate::RedactionTextOutput;

impl Redactor {
    /// Redacts an argument vector through one completed batch operation.
    #[must_use]
    pub fn redact_argv<'items, I>(&self, items: I) -> RedactionTextOutput
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        let mut batch = self.batch();
        let handle = batch.redact_argv(items);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects explicitly classified argv items without rendering them.
    pub fn inspect_argv<'items, I>(&self, items: I) -> RedactionInspectionResult
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
        let mut batch = self.batch();
        let handle = batch.redact_heuristic_argv(items);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects argv items using heuristic option classification.
    pub fn inspect_heuristic_argv<'items, I>(&self, items: I) -> RedactionInspectionResult
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
        let mut batch = self.batch();
        let handle = batch.redact_env(name, value);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one environment assignment without rendering it.
    pub fn inspect_env(&self, name: &str, value: &str) -> RedactionInspectionResult {
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
        let mut batch = self.batch();
        let handle = batch.redact_env_pairs(pairs);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects environment assignments without rendering them.
    pub fn inspect_env_pairs<'items, I>(&self, pairs: I) -> RedactionInspectionResult
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        let mut session = self.inspection_runtime();
        crate::formats::env::inspection::inspect_os_pairs(&mut session, pairs);
        session.finish()
    }

    /// Redacts one process command through one completed batch transaction.
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
        let mut batch = self.batch();
        let handle = batch.redact_process(program, arguments, variables);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one process command without rendering its components.
    pub fn inspect_process<'arguments, 'variables, A, E>(
        &self,
        program: &'arguments OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionInspectionResult
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
