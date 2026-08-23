# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact` 是策略感知的 Rust 脱敏运行时。它通过同一个有界诊断 session 处理领域对象、
JSON、HTTP 值、URI、环境变量和进程参数。源对象只被借用，脱敏结果拥有自己的文本。

## 安装

```toml
[dependencies]
qubit-redact = { version = "0.5" }
```

## 快速开始

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

领域类型可自行实现 `Redact`，或使用
[`qubit-redact-derive`](https://crates.io/crates/qubit-redact-derive)：

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

调用 `Redactor::standard().redact(&value)`，或用 `Redactor::new(policy)` 构造显式策略。
输出包含文本和摘要。展示前应检查 `output.summary().completion()`：
`into_complete_text()` 会拒绝不完整输出，`into_text_or_marker("<redaction incomplete>")`
要求调用方明确选择降级标记。运行时没有可变脱敏 trait，不会修改或擦除源对象。

## 能力

- 有界文本、JSON、URI、HTTP、环境变量、argv 和进程渲染；
- 基于 `Sensitivity` 的掩码以及字段、key、路径规则；
- 只报告匹配规则而不输出原始值的 inspection API；
- 借用 `serde_json::Value` 且保持输入不变的解析 JSON API；
- 在一批相关值之间共享预算和摘要的 batch API；
- 可选的 `serde` 与 derive 集成；默认 feature 集保持最小化。

禁用策略会保留原始输出，只应作为明确的本地退出边界使用，不能用于未经审查的日志。

## 延伸阅读

参见[英文用户手册](doc/user_guide.md)、[中文用户手册](doc/user_guide.zh_CN.md)、
[API 文档](https://docs.rs/qubit-redact)和
[derive 文档](https://docs.rs/qubit-redact-derive)。

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
