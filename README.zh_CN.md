# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact` 是策略感知的 Rust 脱敏运行时。它通过同一个有界诊断 session 处理领域对象、
JSON、HTTP 值、URI、环境变量和进程参数。源对象只被借用，脱敏结果拥有自己的文本。

## 快速开始

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["derive"] }
```

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

领域类型可自行实现 `Redact`，或使用
[`qubit-redact-derive`](https://crates.io/crates/qubit-redact-derive)：

```rust
use qubit_redact::RedactionWriter;

pub trait Redact {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);
}
```

调用 `Redactor::standard().redact(&value)`，或用 `Redactor::new(policy)` 构造显式策略。
运行时没有可变脱敏 trait，不会修改或擦除源对象。

## 能力

- 有界文本、JSON、URI、HTTP、环境变量、argv 和进程渲染；
- 基于 `Sensitivity` 的掩码以及字段、key、路径规则；
- 只报告匹配规则而不输出原始值的 inspection API；
- 借用 `serde_json::Value` 且保持输入不变的解析 JSON API；
- 在一批相关值之间共享预算和摘要的 batch API；
- 可选的 `serde` 与 derive 集成。

禁用策略会保留原始输出，只应作为明确的本地退出边界使用，不能用于未经审查的日志。

## 开发

```bash
cargo test --all-features
./align-ci.sh
./ci-check.sh
```

参见[英文用户手册](doc/user_guide.md)、[中文用户手册](doc/user_guide.zh_CN.md)和
[derive 文档](https://docs.rs/qubit-redact-derive)。

## 许可证

Apache-2.0，详见 [LICENSE](LICENSE)。
