# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact` 运行时 crate 的过程派生宏。它为 Rust 领域对象生成安全的脱敏格式化
和显式的破坏性脱敏实现。

## 安装

运行时 crate 与派生 crate 应一起添加：

```toml
[dependencies]
qubit-redact = "0.3"
qubit-redact-derive = "0.3"
```

## 使用方法

```rust
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Credentials {
    #[redact]
    password: String,
}
```

生成的实现会引用 `qubit-redact`，因此运行时 crate 必须是直接依赖。若使用
`#[redact(serde)]`，请启用运行时 crate 的 `serde` feature。

## 文档

有关脱敏策略、支持的字段属性和集成方式，请参阅
[运行时 crate 文档](https://docs.rs/qubit-redact)。

## 许可证

Copyright (c) 2025 - 2026. Haixing Hu. All rights reserved.

本项目基于 Apache License 2.0 授权。完整许可证文本请参阅
[LICENSE](LICENSE)。

## 贡献

欢迎贡献。请保持宏诊断、公共 API 文档和编译测试同步更新。

## 作者

**Haixing Hu** - *Qubit Co. Ltd.*

仓库地址：[https://github.com/qubit-ltd/rs-redact](https://github.com/qubit-ltd/rs-redact)
