# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

`qubit-redact` is a policy-aware Rust redaction runtime. It renders domain
objects, JSON, HTTP values, URIs, environment variables, and process arguments
through one bounded diagnostic session. The source value is borrowed and the
redaction result is owned.

## Installation

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["derive"] }
```

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
```

For a domain type, implement `Redact` or use
[`qubit-redact-derive`](https://crates.io/crates/qubit-redact-derive):

```rust
use qubit_redact::RedactionWriter;

pub trait Redact {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);
}
```

Then call `Redactor::standard().redact(&value)` or construct an explicit policy
with `Redactor::new(policy)`. The runtime has no mutable redaction trait and does
not mutate or erase the source value.

## Capabilities

- bounded text, JSON, URI, HTTP, environment, argv, and process rendering;
- `Sensitivity`-based masking with field, key, and path policy rules;
- inspection APIs that report matched rules without emitting raw values;
- parsed `serde_json::Value` APIs that borrow and leave the input unchanged;
- batch APIs that share one budget and summary across related values;
- optional `serde` and derive integrations.

Disabled policies preserve raw output for explicit local opt-out use. Treat that
mode as a deliberate boundary decision and never use it for unreviewed logs.

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
