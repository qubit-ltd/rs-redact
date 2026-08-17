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
use crate::LogSafeText;
use crate::RedactionSession;
use crate::Redactor;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;

/// JSON-like marker used when an argument list cannot be rendered completely.
const TRUNCATED_LIST: &str = "[\"<truncated>\"]";

/// A borrowed argv façade over one mutable diagnostic session.
pub struct ArgvRedactionSession<'session, 'policy> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> ArgvRedactionSession<'session, 'policy> {
    /// Creates a façade from a mutable diagnostic session.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(
        session: &'session mut RedactionSession<'policy>,
    ) -> Self {
        Self { session }
    }

    /// Redacts explicitly classified argument items.
    ///
    /// Input is pulled lazily. Once the shared input or output budget is
    /// exhausted, the iterator is not advanced again and only a safe marker
    /// or empty value is returned. The result reports `Complete` only after
    /// observing iterator exhaustion, `Truncated` for non-empty safe output
    /// with any omission, and `Exhausted` for empty output.
    #[must_use]
    pub fn redact_items<'items, I>(&mut self, items: I) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
    {
        self.render(items, false)
    }

    /// Redacts explicit items and heuristically classifies plain items.
    ///
    /// Input is pulled lazily and never inspected after the shared session has
    /// reached its terminal output or input boundary. The result reports
    /// `Complete` only after observing iterator exhaustion, `Truncated` for
    /// non-empty safe output with any omission, and `Exhausted` for empty
    /// output.
    #[must_use]
    pub fn redact_heuristically<'items, I>(&mut self, items: I) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
    {
        self.render(items, true)
    }

    /// Renders one item stream while charging each admitted fragment.
    #[must_use]
    fn render<'items, I>(&mut self, items: I, heuristic: bool) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
    {
        let remaining = self.session.remaining_output_bytes();
        if remaining < InputOutputLimit::MIN_OUTPUT_BYTES {
            return RedactedArgv::exhausted();
        }
        let output_limit = self.session.policy().limits().diagnostic_event();
        let builder_limit = InputOutputLimit::builder()
            .max_input_bytes(usize::MAX)
            .max_output_bytes(remaining)
            .build()
            .expect("the remaining session output must be a valid limit");
        let mut builder = RedactedArgv::builder(builder_limit);
        let renderer =
            ArgvRedactor::new(Redactor::new(self.session.policy().clone()));
        let mut locally_truncated = false;
        let mut iterator_exhausted = false;
        let mut pending = None;
        let mut iterator = items.into_iter();

        let opening = self.session.admit(0, output_limit.max_output_bytes(), 1);
        if !matches!(opening, RedactionAdmission::Render { .. }) {
            return admission_fallback(opening);
        }
        self.session.commit_output(1, FragmentCompletion::Complete);

        while !self.session.is_exhausted() {
            let Some(item) = iterator.next() else {
                iterator_exhausted = true;
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
            let (rendered, item_truncated) = if heuristic {
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
            locally_truncated |= item_truncated;
            let before = builder.len();
            let complete = builder.push(&rendered);
            let after = builder.len();
            let completion = if complete && !item_truncated {
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
        builder.finish(locally_truncated || !iterator_exhausted)
    }
}

/// Converts a non-render admission into a safe argv result.
///
/// Fallback admission has already charged the complete marker and therefore
/// maps to non-empty truncated output. Exhaustion maps to the only valid empty
/// result and does not inspect the pending iterator.
#[must_use]
fn admission_fallback(admission: RedactionAdmission) -> RedactedArgv {
    match admission {
        RedactionAdmission::Fallback => RedactedArgv::truncated(
            LogSafeText::from_escaped(TRUNCATED_LIST.to_owned().into()),
        ),
        RedactionAdmission::Exhausted => RedactedArgv::exhausted(),
        RedactionAdmission::Render { .. } => {
            unreachable!("render admission is handled before fallback")
        }
    }
}

impl<'policy> RedactionSession<'policy> {
    /// Configures the argument-vector adapter inside a chainable session.
    #[must_use]
    pub fn argv_with<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut ArgvRedactionSession<'session, 'policy>),
    {
        let mut adapter = ArgvRedactionSession::new(&mut self);
        configure(&mut adapter);
        self
    }

    /// Runs one argv operation through a borrowed closure adapter.
    #[must_use]
    #[inline(always)]
    pub fn argv_with_mut<F, R>(&mut self, configure: F) -> R
    where
        F: for<'session> FnOnce(
            &mut ArgvRedactionSession<'session, 'policy>,
        ) -> R,
    {
        let mut adapter = ArgvRedactionSession::new(self);
        configure(&mut adapter)
    }
}
