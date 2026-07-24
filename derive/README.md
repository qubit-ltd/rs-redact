# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

Procedural derive macros for the `qubit-redact` runtime crate. They generate
safe redacted formatting and explicit destructive redaction for Rust domain
objects.

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
    #[redact]
    password: String,
}
```

The generated implementations reference `qubit-redact`; the runtime crate must
be a direct dependency. To use `#[redact(serde)]`, enable the runtime crate's
`serde` feature.

## Documentation

See the [runtime crate documentation](https://docs.rs/qubit-redact) for
redaction policies, supported field attributes, and integration guidance.

## License

Copyright (c) 2025 - 2026. Haixing Hu. All rights reserved.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
full license text.

## Contributing

Contributions are welcome. Please keep macro diagnostics, public API
documentation, and compile tests current.

## Author

**Haixing Hu** - *Qubit Co. Ltd.*

Repository: [https://github.com/qubit-ltd/rs-redact](https://github.com/qubit-ltd/rs-redact)
