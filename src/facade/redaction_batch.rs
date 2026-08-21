use super::RedactionBatchHandle;
use super::RedactionBatchOutput;
use crate::domain::Redact;
use crate::runtime::RedactionHandle;
use crate::runtime::RedactionSession;

/// Accumulates independently resolvable redaction items under one budget.
pub struct RedactionBatch {
    session: RedactionSession,
}

impl RedactionBatch {
    /// Creates a batch backed by one private runtime transaction.
    #[must_use]
    pub(crate) const fn from_session(session: RedactionSession) -> Self {
        Self { session }
    }
    /// Redacts one field and returns its opaque batch handle.
    pub fn redact_field(&mut self, field: &str, value: &str) -> RedactionBatchHandle {
        let handle = self.session.redact_field(field, value);
        let (batch_id, item_index) = handle.parts();
        RedactionBatchHandle { batch_id, item_index }
    }
    /// Redacts one domain value and returns its opaque batch handle.
    pub fn redact_value<T>(&mut self, value: &T) -> RedactionBatchHandle
    where
        T: Redact + ?Sized,
    {
        let handle = self.session.redact_value(value);
        let (batch_id, item_index) = handle.parts();
        RedactionBatchHandle { batch_id, item_index }
    }
    /// Redacts an explicit argv sequence as one item.
    pub fn redact_argv<'items, I>(&mut self, items: I) -> RedactionBatchHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        Self::wrap(self.session.redact_argv(items))
    }
    /// Redacts an argv sequence with heuristic option classification as one
    /// item.
    pub fn redact_heuristic_argv<'items, I>(&mut self, items: I) -> RedactionBatchHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        let mut handle = None;
        self.session.argv(|argv| {
            handle = Some(argv.redact_heuristic_items(items));
        });
        Self::wrap(handle.expect("argv adapter must return a handle"))
    }
    /// Redacts one environment assignment as one item.
    pub fn redact_env(&mut self, name: &str, value: &str) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_env(name, value))
    }
    /// Redacts environment assignments as one item.
    pub fn redact_env_pairs<'items, I>(&mut self, pairs: I) -> RedactionBatchHandle
    where
        I: IntoIterator<Item = (&'items std::ffi::OsStr, &'items std::ffi::OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        Self::wrap(self.session.redact_env_pairs(pairs))
    }
    /// Redacts one process command as one item.
    pub fn redact_process<'arguments, 'variables, A, E>(
        &mut self,
        program: &'arguments std::ffi::OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionBatchHandle
    where
        A: IntoIterator<Item = crate::formats::argv::ArgvItem<'arguments>>,
        A::IntoIter: ExactSizeIterator,
        E: IntoIterator<Item = (&'variables std::ffi::OsStr, &'variables std::ffi::OsStr)>,
        E::IntoIter: ExactSizeIterator,
    {
        Self::wrap(self.session.redact_process(program, arguments, variables))
    }
    /// Redacts one JSON document as one item.
    #[cfg(feature = "json")]
    pub fn redact_json(&mut self, text: &str) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_json(text))
    }
    /// Redacts one HTTP URL as one item.
    #[cfg(feature = "http")]
    pub fn redact_http_url(&mut self, value: &str) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_http_url(value))
    }
    /// Redacts one HTTP header map as one item.
    #[cfg(feature = "http")]
    pub fn redact_http_headers(&mut self, headers: &http::HeaderMap) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_http_headers(headers))
    }
    /// Redacts one captured HTTP body as one item.
    #[cfg(feature = "http")]
    pub fn redact_http_body(
        &mut self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&http::HeaderValue>,
    ) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_http_body(capture, content_type))
    }
    /// Redacts one captured HTTP body using textual content-type metadata.
    #[cfg(feature = "http")]
    pub fn redact_http_body_with_content_type_text(
        &mut self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> RedactionBatchHandle {
        let mut handle = None;
        let _ = self.session.http(|http| {
            handle = Some(http.redact_body_with_content_type_text(capture, content_type));
        });
        Self::wrap(handle.expect("HTTP body adapter must return a handle"))
    }
    /// Redacts one URI as one item.
    #[cfg(feature = "uri")]
    pub fn redact_uri(&mut self, value: &str) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_uri(value))
    }
    /// Consumes the batch and publishes its item results and summary.
    #[must_use]
    pub fn finish(mut self) -> RedactionBatchOutput {
        RedactionBatchOutput::from_publication(self.session.finish_batch())
    }

    /// Converts the runtime-private handle into its public batch counterpart.
    fn wrap(handle: RedactionHandle) -> RedactionBatchHandle {
        let (batch_id, item_index) = handle.parts();
        RedactionBatchHandle { batch_id, item_index }
    }
}
