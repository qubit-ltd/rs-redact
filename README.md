# qubit-redact

`qubit-redact` redacts scalar fields, Rust domain values, argv, environment,
process commands, JSON, HTTP, and URI diagnostics under one immutable policy.

## One operation

Each `Redactor` convenience method creates one transaction and returns a
`RedactionOutput`.

```rust
use qubit_redact::Redactor;

let output = Redactor::strict().redact_field("password", "raw-secret");
assert!(!output.text().as_str().contains("raw-secret"));
```

## One diagnostic transaction

Use `RedactionSession` when several fragments must share one input, output, and
structural budget. Aggregate operations return the session for chaining; only
`finish()` publishes text and resets the session for its next transaction.

```rust
use qubit_redact::Redactor;

let mut session = Redactor::strict().session();
session
    .literal("login failed for ")
    .field("user", "Ada")
    .literal(", password: ")
    .field("password", "raw-secret");
let output = session.finish();
assert!(!output.text().as_str().contains("raw-secret"));
```

For separately consumed results, request a `RedactionHandle` and resolve it
only from the output returned by the same completed transaction:

```rust
use qubit_redact::Redactor;

let mut session = Redactor::strict().session();
let password = session.redact_field("password", "raw-secret");
let output = session.finish();
assert!(!output.resolve(password)?.text().as_str().contains("raw-secret"));
# Ok::<(), qubit_redact::RedactionHandleError>(())
```

`literal` accepts only program-authored `&'static str` and still consumes the
shared output budget. Dynamic text must pass through an appropriate redaction
operation.

## Application default

`Redactor::default()` is always the deterministic standard policy. Applications
can install a complete snapshot for `Redact::redacted()` with
`Redactor::replace_application_default`; existing redactors and sessions keep
their own snapshots.

## Domain values

Implement `Redact` or use `qubit-redact-derive`. Fields without a
`#[redact(...)]` annotation, and fields explicitly marked `skip`, are
intentionally unredacted. Sensitive fields must therefore be annotated
explicitly. `RedactionWriter::literal` accepts only program literals;
`RedactionWriter::unredacted` is the explicit escape hatch for trusted dynamic
content.

## License

Apache-2.0.
