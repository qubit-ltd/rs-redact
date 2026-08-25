// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
// qubit-style: allow multiple-public-types
//! Aggregate process-command rendering through one borrowed transaction.

use std::ffi::OsStr;

use super::command_items::CommandItems;
use crate::formats::argv::ArgvItem;
use crate::formats::argv::ArgvRedactionWriter;
use crate::formats::env::EnvRedactionWriter;
use crate::runtime::TextSession;
use crate::runtime::runtime_session::RuntimeSession;

/// A borrowed process-command facade over one active redaction transaction.
///
/// This type owns no redactor, policy, result, or budget. Each operation
/// delegates directly to the argv or environment namespace of the parent
/// session, so process diagnostics participate in the same atomic output.
pub struct ProcessRedactionWriter<'session> {
    /// The transaction receiving every rendered process component.
    session: &'session mut TextSession,
}

impl<'session> ProcessRedactionWriter<'session> {
    /// Creates a process facade that borrows `session` for one adapter closure.
    ///
    /// # Parameters
    ///
    /// * `session` - The active transaction that owns policy, budget, and
    ///   unpublished output.
    ///
    /// # Returns
    ///
    /// A façade that cannot outlive the borrowed transaction.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts a complete process command into the parent aggregate output.
    ///
    /// `program` is inserted as the first argv item. `arguments` therefore
    /// must contain only the arguments following the executable. Each argument
    /// preserves caller-supplied [`ArgvItem`] sensitivity. `variables` uses
    /// borrowed operating-system name/value pairs and is rendered after argv.
    /// No key or independently published result is created.
    ///
    /// # Type Parameters
    ///
    /// * `'arguments` - Lifetime of borrowed argument values.
    /// * `A` - Finite argument source.
    /// * `'variables` - Lifetime of borrowed environment names and values.
    /// * `E` - Finite environment source.
    ///
    /// # Parameters
    ///
    /// * `program` - Executable path or program name.
    /// * `arguments` - Arguments after `program`.
    /// * `variables` - Environment-variable pairs associated with the command.
    ///
    /// # Returns
    ///
    /// This facade for further aggregate process operations.
    pub fn command<'arguments, 'variables, A, E>(
        &mut self,
        program: &'arguments OsStr,
        arguments: A,
        variables: E,
    ) -> &mut Self
    where
        A: IntoIterator<Item = ArgvItem<'arguments>>,
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
    {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        let arguments = arguments.into_iter();
        let mut argv = ArgvRedactionWriter::new(self.session);
        argv.heuristic_items(CommandItems::new(ArgvItem::plain(program), arguments));
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        let mut environment = EnvRedactionWriter::new(self.session);
        environment.os_pairs(variables);
        self
    }

    /// Redacts command-line arguments into the parent aggregate output.
    ///
    /// Plain arguments use the argv namespace's documented heuristic rules;
    /// explicitly sensitive [`ArgvItem`] values are masked at their supplied
    /// sensitivity. No key or standalone output is created.
    ///
    /// # Type Parameters
    ///
    /// * `'arguments` - Lifetime of borrowed argument values.
    /// * `A` - Finite argument source.
    ///
    /// # Parameters
    ///
    /// * `arguments` - Borrowed argv items to render.
    ///
    /// # Returns
    ///
    /// This facade for further aggregate process operations.
    pub fn arguments<'arguments, A>(&mut self, arguments: A) -> &mut Self
    where
        A: IntoIterator<Item = ArgvItem<'arguments>>,
    {
        let mut argv = ArgvRedactionWriter::new(self.session);
        argv.heuristic_items(arguments);
        self
    }

    /// Redacts process environment variables into the parent aggregate output.
    ///
    /// Names and values remain borrowed until the environment namespace has
    /// processed them. No key or standalone output is created.
    ///
    /// # Type Parameters
    ///
    /// * `'variables` - Lifetime of borrowed environment names and values.
    /// * `E` - Finite environment source.
    ///
    /// # Parameters
    ///
    /// * `variables` - Borrowed operating-system environment name/value pairs.
    ///
    /// # Returns
    ///
    /// This facade for further aggregate process operations.
    pub fn variables<'variables, E>(&mut self, variables: E) -> &mut Self
    where
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
    {
        let mut env = EnvRedactionWriter::new(self.session);
        env.os_pairs(variables);
        self
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::ProcessRedactionWriter;
    use crate::Redactor;
    use crate::formats::argv::ArgvItem;

    /// Verifies process components are appended to the one borrowed session.
    #[test]
    fn test_command_appends_redacted_argv_and_environment_to_parent_session() {
        let arguments = [
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new("argv-secret")),
        ];
        let variables = [(OsStr::new("PASSWORD"), OsStr::new("env-secret"))];
        let mut session = Redactor::strict().text_runtime();
        let mut process = ProcessRedactionWriter::new(&mut session);

        process.command(OsStr::new("client"), arguments, variables);

        let output = session.finish();
        assert!(!output.text().as_str().contains("argv-secret"));
        assert!(!output.text().as_str().contains("env-secret"));
    }
}
