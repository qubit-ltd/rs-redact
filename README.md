# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

`qubit-redact` is a policy-aware Rust redaction runtime for application and
library authors who need useful diagnostics without exposing secrets. It
renders borrowed domain objects, JSON, HTTP values, URIs, environment
variables, and process arguments through one bounded session, then returns an
owned redacted result.

## Installation

```toml
[dependencies]
qubit-redact = { version = "0.5" }
```

The default feature set is empty. Enable integrations explicitly, for example
`features = ["derive"]` for `#[derive(Redact)]`, or
`features = ["serde", "derive"]` for derived redacted serialization.

## Quick Start

```rust
use qubit_redact::Redactor;

let output = Redactor::standard()
    .text_composer()
    .literal("user=")
    .field("user", "ada")
    .literal(" password=")
    .field("password", "raw-password")
    .finish();

assert!(output.text().as_str().contains("ada"));
assert!(!output.text().as_str().contains("raw-password"));
let text = output
    .into_complete_text()
    .expect("the default budget must retain this example");
assert!(text.as_str().contains("ada"));
```

For a domain type, implement `Redact` or use
[`qubit-redact-derive`](https://crates.io/crates/qubit-redact-derive):

```rust
use qubit_redact::{Redact, RedactionWriter, Sensitivity};

struct Login { user: String, password: String }

impl Redact for Login {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Login", |fields| {
            fields.unmarked("user", || self.user.as_str());
            fields.sensitive(Sensitivity::Secret, "password", || self.password.as_str());
        });
    }
}
```

Then call `Redactor::standard().redact(&value)` or construct an explicit policy
with `Redactor::new(policy)`. When redaction is enabled, the text remains
confidentiality-safe for `Complete`, `Truncated`, and `Exhausted`; the latter
two states mean only that diagnostic information is incomplete. `Debug`,
`Display`, and ordinary logs may render `output.text()` directly. Inspect
`output.summary()` only when completeness affects auditing, retry, or program
logic. `into_complete_text()` and the marker helpers remain available for such
explicit presentation policies.

For several independently formatted diagnostic values, select one fallback
once and resolve every handle without error-handling boilerplate:

```rust
use qubit_redact::Redactor;

let mut batch = Redactor::standard().batch();
let user = batch.redact_field("user", "ada");
let password = batch.redact_field("password", "raw-password");
let diagnostics = batch.finish_for_diagnostics("<redaction incomplete>");

assert_eq!(diagnostics.text(user).as_str(), "ada");
assert!(!diagnostics.text(password).as_str().contains("raw-password"));
```

Unannotated derive fields and values written through `unmarked` are
intentionally unredacted. Field sensitivity is application-domain knowledge:
the framework cannot infer it reliably and should not force explicit
"non-sensitive" annotations onto the ordinary majority of fields. Downstream
types must explicitly mark sensitive fields and review that decision when their
domain model changes. The runtime does not mutate or erase the source value.

## Why This Project Exists

Diagnostic values commonly cross logging, error-reporting, and support
boundaries before their sensitivity has been reviewed. Ad-hoc masking makes
each call site choose its own format, limits, and fallback behavior. This crate
keeps those decisions in one immutable policy snapshot, shares one bounded
budget across related output, and lets callers observe whether the published
diagnostic is complete without reformatting its source.

## Capabilities

- bounded text, JSON, URI, HTTP, environment, argv, and process rendering;
- `Sensitivity`-based masking with field, key, and path policy rules;
- inspection APIs that report matched rules without emitting raw values;
- parsed `serde_json::Value` APIs that borrow and leave the input unchanged;
- JSON text follows `qubit-json`'s numeric boundary: negative integers fit
  `i64`, non-negative integers fit `u64`, and fractions are finite `f64`;
- batch APIs that share one budget and summary across related values;
- opt-in `serde` and derive integrations; the default feature set is minimal.

It does not infer application-specific sensitivity, erase source memory, or
protect logging and serialization paths that do not use this runtime.

Disabled policies intentionally restore every supported raw value. This is a
deliberate process-wide debugging escape hatch, not an attempt by the framework
to authorize its use. Limits and control-character escaping remain active, but
confidentiality redaction does not. Downstream code owns authorization, timing,
environment controls, and any misuse. Replacing the application default affects
future snapshots; existing redactors, composers, and batches retain the policy
snapshot they already own.

## Learn More

Read the [English user guide](doc/user_guide.md), [中文用户手册](doc/user_guide.zh_CN.md),
[API documentation](https://docs.rs/qubit-redact), and
[derive documentation](https://docs.rs/qubit-redact-derive).

## Testing

```bash
# Run tests with the default feature set
cargo test

# Run tests with all declared features
cargo test --all-features

# Project CI checks
./ci-check.sh

# Check code coverage
./coverage.sh
```

## License

Copyright (c) 2025 - 2026. Haixing Hu. All rights reserved.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
full license text.

## Contributing

Contributions are welcome. Please follow the Rust API guidelines, keep public
API documentation and tests current, and run `./align-ci.sh` to format code and
`./ci-check.sh` to satisfy CI requirements before submitting a pull request.

## Author

**Haixing Hu** - *Qubit Co. Ltd.*

Repository: [https://github.com/qubit-ltd/rs-redact](https://github.com/qubit-ltd/rs-redact)
