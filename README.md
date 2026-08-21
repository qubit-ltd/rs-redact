# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

`qubit-redact` produces bounded, log-safe diagnostic text from fields, Rust
domain values, command data, JSON, HTTP, and URIs. It is for applications that
need one coherent redaction decision for a whole event, rather than a separate
policy, budget, and publication point for every value they log.

## Installation

Choose only the format integrations your application uses:

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["http", "json", "uri"] }
```

The minimum supported Rust version is 1.94. `serde`, `json`, `http`, and `uri`
are optional features. Field, domain, argv, environment, and process redaction
are available with the default feature set.

## Quick Start

An API client wants one failure message and a separately retained URL for
telemetry. The access token must never be published. Build the immutable policy
once; use a text composer for the message and a batch for independently
resolvable telemetry values:

```rust
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

let policy = RedactionPolicy::builder()
    .fields(|fields| {
        fields.secret_sensitive("access_token");
    })?
    .limits(|limits| {
        limits.max_input_bytes(64 * 1024).max_output_bytes(16 * 1024);
    })?
    .build()?;

let redactor = Redactor::new(policy);
let output = redactor
    .text_composer()
    .literal("request failed: ")
    .field("request_id", "req-42")
    .finish();

let mut batch = redactor.batch();
let url = batch.redact_http_url(
    "https://api.example.test/users?access_token=raw-secret",
);
let batch_output = batch.finish();
let safe_url = batch_output.resolve(url)?;
assert_eq!(output.text().as_str(), "request failed: req-42");
assert_eq!(
    safe_url.text().as_str(),
    "https://api.example.test/users?access_token=%3Credacted%3E",
);

# Ok::<(), Box<dyn std::error::Error>>(())
```

Both consuming `finish()` methods are publication boundaries.
`RedactedTextComposer` publishes one ordered `RedactionTextOutput`;
`RedactionBatch` publishes independently resolvable items through opaque
`RedactionBatchHandle` values and `RedactionBatchOutput`. The two objects own
separate resource budgets.

## Why This Project Exists

Independent formatting helpers are easy to compose but easy to get wrong: a
URL and a response body can use different rules, each can consume an unrelated
output allowance, and partially rendered data can escape before a callback
fails. The composer and batch keep their respective work private while it is
being assembled, and `finish()` atomically publishes the completed result. If
user redaction code panics, the active unpublished result is discarded and
unwinding continues. A caught batch panic leaves that batch empty and reusable;
handles created before the panic are invalid.

## What It Provides

- Immutable `RedactionPolicy` snapshots, including deterministic `standard()`
  and fail-closed `strict()` policies.
- Transactional configuration of field rules, masking, limits, and enabled
  HTTP/URI/JSON behavior.
- `RedactedTextComposer` APIs for aggregate text and `RedactionBatch` APIs for
  independently resolved argv, environment, process, JSON, HTTP, and URI data.
- Explicit domain rendering through `Redact` and `RedactionWriter`.
- Machine-readable completion, reasons, and usage in `RedactionSummary`.
- UTF-8, log-safe output that safely degrades when an input, output, or
  structural limit is reached.

The crate does not discover secrets from arbitrary value contents. Review each
business field and mark it deliberately. `unredacted` is an explicit trust
boundary, not a convenience escape hatch; it must receive only independently
reviewed safe data. Limits apply to the complete diagnostic event, not to each
format in isolation.

## Learn More

- [English user guide](doc/user_guide.md)
- [中文用户指南](doc/user_guide.zh_CN.md)
- [API documentation](https://docs.rs/qubit-redact)
- [核心设计（中文）](doc/design.zh_CN.md)

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
