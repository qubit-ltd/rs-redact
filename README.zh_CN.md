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

默认 feature 集为空。集成能力必须显式启用，例如使用 `features = ["derive"]`
获得 `#[derive(Redact)]`，或使用 `features = ["serde", "derive"]` 获得派生的
脱敏序列化。

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
启用脱敏时，`Complete`、`Truncated`、`Exhausted` 三种状态下的文本都满足保密安全要求；
后两者只表示诊断信息不完整。`Debug`、`Display` 和普通日志可以直接展示
`output.text()`。只有审计、重试或业务逻辑依赖完整性时，才需要检查
`output.summary()`；这类调用方仍可使用 `into_complete_text()` 或 marker helper。

一批互相独立的诊断值可以只选择一次降级标记，再无错误样板地解析所有 handle：

```rust
use qubit_redact::Redactor;

let mut batch = Redactor::standard().batch();
let user = batch.redact_field("user", "ada");
let password = batch.redact_field("password", "raw-password");
let diagnostics = batch.finish_for_diagnostics("<redaction incomplete>");

assert_eq!(diagnostics.text(user).as_str(), "ada");
assert!(!diagnostics.text(password).as_str().contains("raw-password"));
```

derive 未标注字段和通过 `unmarked` 写入的值会有意保持不脱敏。字段是否敏感属于下游业务
领域知识，框架既无法可靠推断，也不应要求占绝大多数的普通字段逐一声明“不敏感”。下游
类型应显式标记敏感字段，并在领域模型变化时重新审查。运行时不会修改或擦除源对象。

## 能力

- 有界文本、JSON、URI、HTTP、环境变量、argv 和进程渲染；
- 基于 `Sensitivity` 的掩码以及字段、key、路径规则；
- 只报告匹配规则而不输出原始值的 inspection API；
- 借用 `serde_json::Value` 且保持输入不变的解析 JSON API；
- JSON 文本遵循 `qubit-json` 数字边界：负整数装入 `i64`，非负整数装入 `u64`，小数为有限
  `f64`；
- 在一批相关值之间共享预算和摘要的 batch API；
- 可选的 `serde` 与 derive 集成；默认 feature 集保持最小化。

禁用策略会有意恢复所有支持入口的原值。这是框架特意保留的进程级调试逃生口，不代表框架
替下游授权。资源限制和控制字符转义仍然生效，但保密脱敏不再生效；授权、调用时机、运行
环境和误用后果由下游负责。替换应用默认值只影响之后取得的策略快照，已经创建的
`Redactor`、composer 和 batch 继续持有原快照。

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
