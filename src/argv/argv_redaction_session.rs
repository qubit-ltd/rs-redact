// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared-session argument-vector redaction.

use super::ArgvItem;
use super::ArgvRedactor;
use super::RedactedArgv;
use crate::InputOutputLimit;
use crate::RedactionSession;
use crate::Redactor;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;

const TRUNCATED_LIST: &str = "[\"<truncated>\"]";

/// A borrowed argv façade over one mutable diagnostic session.
#[must_use = "use the façade to produce the redacted argv rendering"]
pub struct ArgvRedactionSession<'session, 'policy> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> ArgvRedactionSession<'session, 'policy> {
    /// Creates a façade from a mutable diagnostic session.
    #[inline(always)]
    pub(crate) const fn new(
        session: &'session mut RedactionSession<'policy>,
    ) -> Self {
        Self { session }
    }

    /// Redacts explicitly classified argument items.
    ///
    /// Input is pulled lazily. Once the shared input or output budget is
    /// exhausted, the iterator is not advanced again and only a safe marker
    /// or empty value is returned.
    pub fn redact_items<'items, I>(&mut self, items: I) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
    {
        self.render(items, false)
    }

    /// Redacts explicit items and heuristically classifies plain items.
    ///
    /// Input is pulled lazily and never inspected after the shared session has
    /// reached its terminal output or input boundary.
    pub fn redact_heuristically<'items, I>(&mut self, items: I) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
    {
        self.render(items, true)
    }

    /// Renders one item stream while charging each admitted fragment.
    fn render<'items, I>(&mut self, items: I, heuristic: bool) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
    {
        let remaining = self.session.remaining_output_bytes();
        if remaining < InputOutputLimit::MIN_OUTPUT_BYTES {
            return RedactedArgv::from_rendered(String::new());
        }
        let output_limit = self.session.policy().limits().diagnostic_event();
        let builder_limit = InputOutputLimit::new(usize::MAX, remaining)
            .expect("the remaining session output must be a valid limit");
        let mut builder = RedactedArgv::builder(builder_limit);
        let renderer =
            ArgvRedactor::new(Redactor::new(self.session.policy().clone()));
        let mut pending = None;
        let mut iterator = items.into_iter();

        let opening = self.session.admit(0, output_limit.max_output_bytes(), 1);
        if !matches!(opening, RedactionAdmission::Render { .. }) {
            return admission_fallback(opening);
        }
        self.session.commit_output(1, FragmentCompletion::Complete);

        while !self.session.is_exhausted() {
            let Some(item) = iterator.next() else {
                break;
            };
            let admission = self.session.admit(
                item.value().as_encoded_bytes().len(),
                output_limit.max_output_bytes(),
                TRUNCATED_LIST.len(),
            );
            let RedactionAdmission::Render { max_output_bytes } = admission
            else {
                return admission_fallback(admission);
            };
            let rendered = if heuristic {
                if let Some(level) = item.sensitivity() {
                    pending = None;
                    renderer.mask_os_value_bounded(
                        item.value(),
                        level,
                        max_output_bytes,
                    )
                } else {
                    renderer.redact_plain_item_bounded(
                        item.value(),
                        &mut pending,
                        max_output_bytes,
                    )
                }
            } else {
                renderer
                    .render_explicit_or_plain_bounded(item, max_output_bytes)
            };
            let before = builder.len();
            let complete = builder.push(&rendered);
            let after = builder.len();
            let completion = if complete {
                FragmentCompletion::Complete
            } else {
                FragmentCompletion::SessionTruncated
            };
            self.session.commit_output(after - before, completion);
            if !complete {
                break;
            }
        }

        if self.session.remaining_output_bytes() >= 1 && !builder.is_truncated()
        {
            let admission =
                self.session.admit(0, output_limit.max_output_bytes(), 1);
            if let RedactionAdmission::Render { .. } = admission {
                let before = builder.len();
                builder.close();
                let after = builder.len();
                let completion = if builder.is_truncated() {
                    FragmentCompletion::SessionTruncated
                } else {
                    FragmentCompletion::Complete
                };
                self.session.commit_output(after - before, completion);
            }
        }
        builder.finish()
    }
}

/// Converts a non-render admission into a safe argv result.
fn admission_fallback(admission: RedactionAdmission) -> RedactedArgv {
    match admission {
        RedactionAdmission::Fallback => {
            RedactedArgv::from_rendered(TRUNCATED_LIST.to_owned())
        }
        RedactionAdmission::Exhausted => {
            RedactedArgv::from_rendered(String::new())
        }
        RedactionAdmission::Render { .. } => {
            unreachable!("render admission is handled before fallback")
        }
    }
}

impl<'policy> RedactionSession<'policy> {
    /// Creates an argv façade borrowing this diagnostic session.
    #[inline(always)]
    pub fn argv<'session>(
        &'session mut self,
    ) -> ArgvRedactionSession<'session, 'policy> {
        ArgvRedactionSession::new(self)
    }
}
