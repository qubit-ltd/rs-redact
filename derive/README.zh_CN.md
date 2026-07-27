# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact` 运行时 crate 的过程派生宏。它为 Rust 领域对象生成安全的脱敏格式化
和显式的逻辑原地脱敏实现。

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
    #[redact(level = "secret")]
    password: String,
}
```

生成的实现会引用 `qubit-redact`，因此运行时 crate 必须是直接依赖。若使用
`#[redact(serde)]`，请启用运行时 crate 的 `serde` feature。

## 文档

有关脱敏策略、支持的字段属性和集成方式，请参阅
[运行时 crate 文档](https://docs.rs/qubit-redact)。

## 测试

```bash
# 使用默认 feature 集运行测试
cargo test

# 使用项目声明的全部 feature 运行测试
cargo test --all-features

# 运行项目 CI 检查
./ci-check.sh

# 检查代码覆盖率
./coverage.sh
```

## 许可证

Copyright (c) 2025 - 2026. Haixing Hu. All rights reserved.

本项目基于 Apache License 2.0 授权。完整许可证文本请参阅
[LICENSE](LICENSE)。

## 贡献

欢迎贡献。请遵循 Rust API 指南，及时更新公共 API 文档与测试，并在提交
Pull Request 前运行 `./align-ci.sh`格式化代码，运行`./ci-check.sh`对齐CI要求。

## 作者

**Haixing Hu** - *Qubit Co. Ltd.*

仓库地址：[https://github.com/qubit-ltd/rs-redact](https://github.com/qubit-ltd/rs-redact)
