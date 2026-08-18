// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared-session environment redaction.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Write as _;

use super::EnvRedactor;
use super::RedactedEnv;
use super::RedactedEnvPair;
use super::env_redactor::write_debug_item;
use crate::InputOutputLimit;
use crate::LogOutputLimit;
use crate::RedactedText;
use crate::RedactionSession;
use crate::Redactor;
use crate::output::internal::BoundedLogEscapeWriter;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;

/// Safe key/value marker used when an environment pair cannot be rendered.
const FALLBACK_PAIR: &str = "<redacted>=<redacted>";
/// Safe marker used when the environment list is truncated.
const TRUNCATED_LIST: &str = "<truncated>";

/// A borrowed environment façade over one mutable diagnostic session.
pub struct EnvRedactionSession<'session, 'policy> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> EnvRedactionSession<'session, 'policy> {
    /// Creates a façade from a mutable diagnostic session.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(session: &'session mut RedactionSession<'policy>) -> Self {
        Self { session }
    }

    /// Redacts one pair and stages the committed result under `key`.
    pub fn redact_pair_as(&mut self, key: &str, name: &str, value: &str) -> &mut Self {
        let result = self.redact_pair(name, value);
        let completion = result.completion();
        self.session.stage_text(key, result.into_log_safe_text(), completion);
        self
    }

    /// Redacts one UTF-8 environment pair.
    #[must_use]
    pub fn redact_pair(&mut self, name: &str, value: &str) -> RedactedEnvPair {
        self.redact_os_pair(OsStr::new(name), OsStr::new(value))
    }

    /// Redacts one possibly non-UTF-8 environment pair.
    #[must_use]
    pub fn redact_os_pair(&mut self, name: &OsStr, value: &OsStr) -> RedactedEnvPair {
        let input_bytes = name
            .as_encoded_bytes()
            .len()
            .saturating_add(value.as_encoded_bytes().len());
        let domain_limit = self.session.policy().limits().diagnostic_event().max_output_bytes();
        let admission = self.session.admit(input_bytes, domain_limit, FALLBACK_PAIR.len());
        let RedactionAdmission::Render { max_output_bytes } = admission else {
            return pair_fallback(admission);
        };
        let renderer = EnvRedactor::new(Redactor::new(self.session.policy().clone()));
        let (rendered, locally_truncated) = renderer.redact_os_pair_bounded(name, value, max_output_bytes);
        if rendered.len() > max_output_bytes {
            let fallback = if FALLBACK_PAIR.len() <= max_output_bytes {
                FALLBACK_PAIR
            } else {
                ""
            };
            self.session
                .commit_output(fallback.len(), FragmentCompletion::SessionTruncated);
            return if fallback.is_empty() {
                RedactedEnvPair::exhausted()
            } else {
                RedactedEnvPair::truncated(log_safe_rendered(fallback.to_owned()))
            };
        }
        let completion = if locally_truncated {
            FragmentCompletion::SessionTruncated
        } else {
            FragmentCompletion::Complete
        };
        self.session.commit_output(rendered.len(), completion);
        if locally_truncated {
            RedactedEnvPair::truncated(log_safe_rendered(rendered))
        } else {
            RedactedEnvPair::complete(log_safe_rendered(rendered))
        }
    }

    /// Redacts a lazily supplied list of environment pairs.
    ///
    /// Pairs are admitted and pulled one at a time. A complete batch preserves
    /// its debug-style list, a truncated batch contains non-empty safe
    /// substitute text, and exhaustion returns empty safe text without
    /// advancing `pairs` again.
    ///
    /// # Type Parameters
    ///
    /// * `'items` - Lifetime of names and values yielded by `pairs`.
    /// * `I` - Iterator source yielding borrowed environment pairs.
    ///
    /// # Parameters
    ///
    /// * `pairs` - Lazily supplied environment names and values.
    ///
    /// # Returns
    ///
    /// A [`RedactedEnv`] carrying the batch text and exact completion state.
    #[must_use]
    pub fn redact_os_pairs<'items, I>(&mut self, pairs: I) -> RedactedEnv
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        let remaining = self.session.remaining_output_bytes();
        if remaining < InputOutputLimit::MIN_OUTPUT_BYTES {
            return RedactedEnv::exhausted();
        }
        let domain_limit = self.session.policy().limits().diagnostic_event().max_output_bytes();
        let writer_limit = LogOutputLimit::from(
            InputOutputLimit::builder()
                .max_input_bytes(usize::MAX)
                .max_output_bytes(remaining)
                .build()
                .expect("the remaining session output must be a valid limit"),
        );
        let mut writer = BoundedLogEscapeWriter::new(writer_limit);
        let mut has_item = false;
        let mut iterator_exhausted = false;
        let mut locally_truncated = false;
        let mut iterator = pairs.into_iter();

        let open = self.session.admit(0, domain_limit, 1);
        if !matches!(open, RedactionAdmission::Render { .. }) {
            return list_fallback(open);
        }
        let before = writer.len();
        let _ = writer.write_str("[");
        self.session
            .commit_output(writer.len() - before, FragmentCompletion::Complete);

        while !self.session.is_exhausted() {
            let Some((name, value)) = iterator.next() else {
                iterator_exhausted = true;
                break;
            };
            let input_bytes = name
                .as_encoded_bytes()
                .len()
                .saturating_add(value.as_encoded_bytes().len());
            let admission = self.session.admit(input_bytes, domain_limit, TRUNCATED_LIST.len());
            let RedactionAdmission::Render { max_output_bytes } = admission else {
                return list_fallback(admission);
            };
            let renderer = EnvRedactor::new(Redactor::new(self.session.policy().clone()));
            let (pair, pair_truncated) = renderer.redact_os_pair_bounded(name, value, max_output_bytes);
            locally_truncated |= pair_truncated;
            let before = writer.len();
            write_debug_item(&mut writer, &mut has_item, &pair);
            let complete = !writer.is_truncated();
            self.session.commit_output(
                writer.len() - before,
                if complete && !pair_truncated {
                    FragmentCompletion::Complete
                } else {
                    FragmentCompletion::SessionTruncated
                },
            );
            if !complete {
                return RedactedEnv::truncated(log_safe_rendered(TRUNCATED_LIST.to_owned()));
            }
        }

        if self.session.remaining_output_bytes() == 0 || writer.is_truncated() {
            return RedactedEnv::truncated(log_safe_rendered(TRUNCATED_LIST.to_owned()));
        }
        if self.session.remaining_output_bytes() >= 1 && !writer.is_truncated() {
            let close = self.session.admit(0, domain_limit, 1);
            if matches!(close, RedactionAdmission::Render { .. }) {
                let before = writer.len();
                let _ = writer.write_str("]");
                self.session.commit_output(
                    writer.len() - before,
                    if writer.is_truncated() {
                        FragmentCompletion::SessionTruncated
                    } else {
                        FragmentCompletion::Complete
                    },
                );
            }
        }
        let writer_truncated = writer.is_truncated();
        let rendered = log_safe_rendered(writer.finish());
        if locally_truncated || !iterator_exhausted || writer_truncated {
            RedactedEnv::truncated(rendered)
        } else {
            RedactedEnv::complete(rendered)
        }
    }
}

/// Converts a non-render admission into a safe pair.
#[must_use]
fn pair_fallback(admission: RedactionAdmission) -> RedactedEnvPair {
    match admission {
        RedactionAdmission::Fallback => RedactedEnvPair::truncated(log_safe_rendered(FALLBACK_PAIR.to_owned())),
        RedactionAdmission::Exhausted => RedactedEnvPair::exhausted(),
        RedactionAdmission::Render { .. } => {
            unreachable!("render admission is handled before fallback")
        }
    }
}

/// Converts a non-render admission into a completion-aware batch result.
///
/// Fallback admission has already charged non-empty substitute text and maps
/// to truncation. Exhausted admission maps to empty output and callers must not
/// advance the pending iterator.
#[must_use]
fn list_fallback(admission: RedactionAdmission) -> RedactedEnv {
    match admission {
        RedactionAdmission::Fallback => RedactedEnv::truncated(log_safe_rendered(TRUNCATED_LIST.to_owned())),
        RedactionAdmission::Exhausted => RedactedEnv::exhausted(),
        RedactionAdmission::Render { .. } => {
            unreachable!("render admission is handled before fallback")
        }
    }
}

/// Labels an already escaped rendered value as log-safe.
///
/// # Parameters
///
/// * `value` - Escaped adapter output that contains no raw source controls.
///
/// # Returns
///
/// Owned typed log-safe output without applying a second escape pass.
#[inline(always)]
#[must_use]
fn log_safe_rendered(value: String) -> RedactedText {
    RedactedText::from_escaped(Cow::Owned(value))
}

impl<'policy> RedactionSession<'policy> {
    /// Configures the environment adapter inside a chainable session.
    #[must_use]
    pub fn env_with<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut EnvRedactionSession<'session, 'policy>),
    {
        let mut adapter = EnvRedactionSession::new(&mut self);
        configure(&mut adapter);
        self
    }

    /// Runs one environment operation through a borrowed closure adapter.
    #[must_use]
    #[inline(always)]
    pub fn env_with_mut<F, R>(&mut self, configure: F) -> R
    where
        F: for<'session> FnOnce(&mut EnvRedactionSession<'session, 'policy>) -> R,
    {
        let mut adapter = EnvRedactionSession::new(self);
        configure(&mut adapter)
    }
}
