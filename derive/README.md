# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

Procedural derive macros for the `qubit-redact` runtime crate. They generate
safe redacted formatting and explicit logical in-place redaction for Rust
domain objects.

## Installation

Add the runtime crate and this derive crate together:

```toml
[dependencies]
qubit-redact = "0.3"
qubit-redact-derive = "0.3"
```

## Usage

```rust
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Credentials {
    #[redact(level = "secret")]
    password: String,
}
```

The generated implementations reference `qubit-redact`; the runtime crate must
be a direct dependency. To use `#[redact(serde)]`, enable the runtime crate's
`serde` feature.

## Documentation

See the [runtime crate documentation](https://docs.rs/qubit-redact) for
redaction policies, supported field attributes, and integration guidance.

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
