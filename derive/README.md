# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

Qubit Redact Derive provides procedural macros for the
[`qubit-redact`](https://crates.io/crates/qubit-redact) runtime crate. Use
them to define a deliberate redaction boundary for Rust domain objects: create
safe borrowed diagnostic views with `Redact`, or explicitly replace logical
values with `RedactMut`.

## Why qubit-redact-derive

- Field annotations make masking, omission, nested redaction, and map
  redaction reviewable at the domain-model boundary.
- The macros support named, tuple, and unit structs, plus enums with all three
  variant shapes.
- Optional Serde support serializes a redacted view without granting it
  deserialization or exposing an original-value escape hatch.
- The generated code resolves a direct `qubit-redact` dependency, including a
  Cargo-renamed dependency, instead of relying on a fixed import spelling.

## Quick Start

Add the runtime and derive crates together:

```toml
[dependencies]
qubit-redact = "0.6"
qubit-redact-derive = "0.6"
```

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Credentials {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let credentials = Credentials {
        user: "ada".to_owned(),
        password: "raw-password".to_owned(),
    };

    let output = format!("{:?}", credentials.redacted());
    assert!(output.contains("ada"));
    assert!(!output.contains("raw-password"));
}
```

`Redact` creates a borrowed view. The original `Credentials` value remains
available to application logic.

For types whose fields must all be reviewed explicitly, add
`#[redact(require_explicit)]`. Mark intentionally visible fields with
`#[redact(plain)]`; the default behavior remains unchanged for existing types.

## Choose a Derive

| Need | Derive | Result |
| --- | --- | --- |
| Safely inspect or log a domain object without changing it | `Redact` | A borrowed `Redacted<T>` view. |
| Serialize an already-redacted object | `Redact` with `#[redact(serde)]` | An opt-in `Serialize` implementation for `Redacted<T>`. |
| Replace owned logical values before another boundary | `RedactMut` | An explicit `redact_in_place()` or `redact_in_place_with(...)` operation. |
| Make an original type format through the process default policy | `Redact` with `#[redact(debug)]` or `#[redact(display)]` | Generated `Debug` and/or `Display` for the original type. |

Use `Redact` for diagnostics whenever possible. Choose `RedactMut` only
when the next boundary requires a logically replaced value.

## Attribute Overview

Field attributes select exactly one handling mode:

| Attribute | Effect |
| --- | --- |
| `#[redact(level = "low|medium|high|secret")]` | Masks the field with the specified runtime sensitivity. |
| `#[redact(plain)]` | Keeps the field visible and documents the intentional pass-through. |
| `#[redact(skip)]` | Omits the field from the redacted view. |
| `#[redact(nested)]` | Delegates redaction to the nested value. |
| `#[redact(map)]` | Redacts text-keyed map values using their keys and the complete runtime policy. |
| `#[redact(json)]` | Redacts JSON stored in a `String` recursively by object key; invalid JSON is replaced opaquely. |

Container attributes are opt-in controls:

| Attribute | Effect |
| --- | --- |
| `#[redact(debug)]` | Generates redacted `Debug` for the original type. |
| `#[redact(display)]` | Generates redacted `Display` for the original type. |
| `#[redact(serde)]` | Generates serialization support for `Redacted<T>`. |
| `#[redact(require_explicit)]` | Requires every field to select one field mode; it does not change the default behavior. |

Unmarked fields use their ordinary `Debug` representation by default. They are
neither masked nor recursively traversed. `require_explicit` changes only the
derive invocation where it is written.

## Dependencies and Features

The generated code requires `qubit-redact` to be a direct dependency. The
derive crate discovers Cargo renames, so this also works:

```toml
[dependencies]
redaction = { package = "qubit-redact", version = "0.6" }
qubit-redact-derive = "0.6"
```

To use `#[redact(serde)]`, enable the runtime crate's `serde` feature and
declare `serde` directly:

```toml
[dependencies]
qubit-redact = { version = "0.6", features = ["serde"] }
qubit-redact-derive = "0.6"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

`#[redact(json)]` requires the runtime crate's `json` feature. It formats a
redacted JSON view, rewrites the string as compact redacted JSON for
`RedactMut`, and serializes as a JSON string when combined with
`#[redact(serde)]`.

## Safety Boundaries

- The macros protect only the redacted view, generated formatting, or explicit
  in-place operation that you use. They cannot protect unrelated log calls or
  serialization paths.
- An unmarked field uses its own `Debug` output. Mark every field whose
  representation can disclose sensitive data, or opt into
  `#[redact(require_explicit)]` and use `#[redact(plain)]` for intentional
  pass-through fields.
- `skip` omits a value from the redacted representation; it does not erase
  the original value.
- `RedactMut` performs logical replacement only. It does not erase released
  allocations, aliases, copies, or borrowed backing storage.
- `debug` and `display` use the process-wide default policy. Use an
  explicit `redacted_with` boundary when a call site needs policy isolation.

## Learn More

- [English User Guide](doc/user_guide.md) and [中文用户手册](doc/user_guide.zh_CN.md)
- [Runtime README](../README.md) and [runtime user guide](../doc/user_guide.md)
- [Runtime API documentation](https://docs.rs/qubit-redact)
- [Derive API documentation](https://docs.rs/qubit-redact-derive)

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
