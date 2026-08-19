# User guide

Choose `Redactor::strict()` unless an application-specific `RedactionPolicy`
has been built and injected explicitly. A `Redactor` owns an immutable policy
snapshot; its `session()` method creates a reusable `RedactionSession` sharing
that snapshot.

All aggregate session operations (`literal`, `field`, `value`, `argv`, `env`,
`process`, `json`, `http`, and `uri`) write one composed result. All individual
operations (`redact_field`, `redact_value`, and format-specific `redact_*`)
return opaque handles. A handle has no text conversion and is valid only after
the transaction's `finish()`.

Every byte of literals, redacted values, escaping, markers, and every format is
charged once against the same session output budget. When that budget is
exhausted, later accessors and adapter closures are not run. A panic from user
redaction code discards the active transaction, resets the session, and resumes
unwinding; nothing from that transaction is published.

`RedactedText` is final, safe redacted text. `RedactionOutput` adds a summary
for one item. `RedactionSessionOutput` adds aggregate text, the aggregate
summary, and handle resolution.

For derived domain types, an unannotated field is intentionally unredacted.
Use `#[redact(...)]` for every sensitive field. Use writer `literal` only for
program literals and `unredacted` only for trusted dynamic content.
