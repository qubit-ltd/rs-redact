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
use super::RedactedEnvPair;
use super::env_redactor::write_debug_item;
use crate::InputOutputLimit;
use crate::LogOutputLimit;
use crate::LogSafeText;
use crate::RedactedText;
use crate::RedactionSession;
use crate::Redactor;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;
use crate::text::internal::BoundedLogEscapeWriter;

const FALLBACK_PAIR: &str = "<redacted>=<redacted>";
const TRUNCATED_LIST: &str = "<truncated>";

/// A borrowed environment façade over one mutable diagnostic session.
#[must_use = "use the façade to produce the redacted environment value"]
pub struct EnvRedactionSession<'session, 'policy> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> EnvRedactionSession<'session, 'policy> {
    /// Creates a façade from a mutable diagnostic session.
    #[inline(always)]
    pub(crate) const fn new(
        session: &'session mut RedactionSession<'policy>,
    ) -> Self {
        Self { session }
    }

    /// Redacts one UTF-8 environment pair.
    pub fn redact_pair(&mut self, name: &str, value: &str) -> RedactedEnvPair {
        self.redact_os_pair(OsStr::new(name), OsStr::new(value))
    }

    /// Redacts one possibly non-UTF-8 environment pair.
    pub fn redact_os_pair(
        &mut self,
        name: &OsStr,
        value: &OsStr,
    ) -> RedactedEnvPair {
        let input_bytes = name
            .as_encoded_bytes()
            .len()
            .saturating_add(value.as_encoded_bytes().len());
        let domain_limit = self
            .session
            .policy()
            .limits()
            .diagnostic_event()
            .max_output_bytes();
        let admission =
            self.session
                .admit(input_bytes, domain_limit, FALLBACK_PAIR.len());
        let RedactionAdmission::Render { max_output_bytes } = admission else {
            return pair_fallback(admission);
        };
        let renderer =
            EnvRedactor::new(Redactor::new(self.session.policy().clone()));
        let rendered =
            renderer.redact_os_pair_bounded(name, value, max_output_bytes);
        if rendered.len() > max_output_bytes {
            let fallback = if FALLBACK_PAIR.len() <= max_output_bytes {
                FALLBACK_PAIR
            } else {
                ""
            };
            self.session.commit_output(
                fallback.len(),
                FragmentCompletion::SessionTruncated,
            );
            return RedactedEnvPair::from_rendered(fallback.to_owned());
        }
        self.session
            .commit_output(rendered.len(), FragmentCompletion::Complete);
        RedactedEnvPair::from_rendered(rendered)
    }

    /// Redacts a lazily supplied list of environment pairs.
    pub fn redact_os_pairs<'items, I>(
        &mut self,
        pairs: I,
    ) -> LogSafeText<'static>
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        let remaining = self.session.remaining_output_bytes();
        if remaining < InputOutputLimit::MIN_OUTPUT_BYTES {
            return log_safe_owned(String::new());
        }
        let domain_limit = self
            .session
            .policy()
            .limits()
            .diagnostic_event()
            .max_output_bytes();
        let writer_limit = LogOutputLimit::from(
            InputOutputLimit::new(usize::MAX, remaining)
                .expect("the remaining session output must be a valid limit"),
        );
        let mut writer = BoundedLogEscapeWriter::new(writer_limit);
        let mut has_item = false;
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
                break;
            };
            let input_bytes = name
                .as_encoded_bytes()
                .len()
                .saturating_add(value.as_encoded_bytes().len());
            let admission = self.session.admit(
                input_bytes,
                domain_limit,
                TRUNCATED_LIST.len(),
            );
            let RedactionAdmission::Render { max_output_bytes } = admission
            else {
                return list_fallback(admission);
            };
            let renderer =
                EnvRedactor::new(Redactor::new(self.session.policy().clone()));
            let pair =
                renderer.redact_os_pair_bounded(name, value, max_output_bytes);
            let before = writer.len();
            write_debug_item(&mut writer, &mut has_item, &pair);
            let complete = !writer.is_truncated();
            self.session.commit_output(
                writer.len() - before,
                if complete {
                    FragmentCompletion::Complete
                } else {
                    FragmentCompletion::SessionTruncated
                },
            );
            if !complete {
                return log_safe_owned(TRUNCATED_LIST.to_owned());
            }
        }

        if self.session.remaining_output_bytes() == 0 || writer.is_truncated() {
            return log_safe_owned(TRUNCATED_LIST.to_owned());
        }
        if self.session.remaining_output_bytes() >= 1 && !writer.is_truncated()
        {
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
        log_safe_owned(writer.finish())
    }
}

/// Converts a non-render admission into a safe pair.
fn pair_fallback(admission: RedactionAdmission) -> RedactedEnvPair {
    match admission {
        RedactionAdmission::Fallback => {
            RedactedEnvPair::from_rendered(FALLBACK_PAIR.to_owned())
        }
        RedactionAdmission::Exhausted => {
            RedactedEnvPair::from_rendered(String::new())
        }
        RedactionAdmission::Render { .. } => {
            unreachable!("render admission is handled before fallback")
        }
    }
}

/// Converts a non-render admission into a safe list marker.
fn list_fallback(admission: RedactionAdmission) -> LogSafeText<'static> {
    match admission {
        RedactionAdmission::Fallback => {
            log_safe_owned(TRUNCATED_LIST.to_owned())
        }
        RedactionAdmission::Exhausted => log_safe_owned(String::new()),
        RedactionAdmission::Render { .. } => {
            unreachable!("render admission is handled before fallback")
        }
    }
}

/// Creates an escaped owned log-safe value.
#[inline(always)]
fn log_safe_owned(value: String) -> LogSafeText<'static> {
    RedactedText::new(Cow::Owned(value)).escape_for_log()
}

impl<'policy> RedactionSession<'policy> {
    /// Creates an environment façade borrowing this diagnostic session.
    #[inline(always)]
    pub fn env<'session>(
        &'session mut self,
    ) -> EnvRedactionSession<'session, 'policy> {
        EnvRedactionSession::new(self)
    }
}
