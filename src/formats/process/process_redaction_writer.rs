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

use super::admitted_command_items::AdmittedCommandItems;
use super::admitted_environment_pairs::AdmittedEnvironmentPairs;
use super::command_items::CommandItems;
use crate::RedactionHandle;
use crate::RedactionReason;
use crate::RedactionSession;
use crate::formats::argv::ArgvItem;
use crate::formats::argv::ArgvRedactionWriter;
use crate::formats::argv::redaction::redact_heuristically_with_policy;
use crate::formats::env::EnvRedactionWriter;
use crate::formats::env::redaction::redact_os_pairs_with_policy;
use crate::runtime::OperationSink;

/// A borrowed process-command facade over one active redaction transaction.
///
/// This type owns no redactor, policy, result, or budget. Each operation
/// delegates directly to the argv or environment namespace of the parent
/// session, so process diagnostics participate in the same atomic output.
pub struct ProcessRedactionWriter<'session> {
    /// The transaction receiving every rendered process component.
    session: &'session mut RedactionSession,
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
    pub(crate) const fn new(session: &'session mut RedactionSession) -> Self {
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
    /// * `A` - Finite argument source with an exact remaining length.
    /// * `'variables` - Lifetime of borrowed environment names and values.
    /// * `E` - Finite environment source with an exact remaining length.
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
        A::IntoIter: ExactSizeIterator,
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
        E::IntoIter: ExactSizeIterator,
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

    /// Redacts a complete process command as one individually resolvable item.
    ///
    /// The argv and environment portions are rendered under the output
    /// capacity still owned by this transaction, then committed together as a
    /// single handle. No temporary session or independent adapter budget is
    /// created.
    #[must_use]
    pub(crate) fn redact_command<'arguments, 'variables, A, E>(
        &mut self,
        program: &'arguments OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionHandle
    where
        A: IntoIterator<Item = ArgvItem<'arguments>>,
        A::IntoIter: ExactSizeIterator,
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
        E::IntoIter: ExactSizeIterator,
    {
        let owns_item_summary = self.session.begin_item_summary();
        let handle = (|| {
            if self.session.is_output_exhausted() {
                return self.exhausted_handle();
            }
            if !self.session.admit_format_node(1) {
                return self.session.stage_accounted_text(String::new());
            }
            let policy = self.session.policy().clone();
            let remaining = self.session.remaining_output_bytes();
            let (argv, command_failed) = {
                let mut command = AdmittedCommandItems {
                    session: self.session,
                    program: Some(ArgvItem::plain(program)),
                    arguments: arguments.into_iter(),
                    failed: false,
                };
                let output = redact_heuristically_with_policy(&policy, &mut command, remaining);
                (output, command.failed)
            };
            if command_failed || !self.session.admit_format_node(1) {
                return self.session.stage_accounted_text(String::new());
            }
            let remaining = remaining.saturating_sub(argv.text().len());
            if remaining == 0 {
                return self.session.stage_rendered_operation(
                    argv.merge(OperationSink::exhausted("", RedactionReason::OutputLimitReached).finish()),
                );
            }
            let (environment, environment_failed) = {
                let mut pairs = AdmittedEnvironmentPairs {
                    session: self.session,
                    variables: variables.into_iter(),
                    failed: false,
                    marker: std::marker::PhantomData,
                };
                let output = redact_os_pairs_with_policy(&policy, &mut pairs, remaining);
                (output, pairs.failed)
            };
            if environment_failed {
                return self.session.stage_accounted_text(String::new());
            }
            self.session.stage_rendered_operation(argv.merge(environment))
        })();
        self.session.end_item_summary(owns_item_summary);
        handle
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
    /// * `A` - Finite argument source with an exact remaining length.
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
        A::IntoIter: ExactSizeIterator,
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
    /// * `E` - Finite environment source with an exact remaining length.
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
        E::IntoIter: ExactSizeIterator,
    {
        let mut env = EnvRedactionWriter::new(self.session);
        env.os_pairs(variables);
        self
    }

    #[must_use]
    fn exhausted_handle(&mut self) -> RedactionHandle {
        self.session.stage_exhausted_handle()
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

        let output = session.finish_text();
        assert!(!output.text().as_str().contains("argv-secret"));
        assert!(!output.text().as_str().contains("env-secret"));
    }
}
