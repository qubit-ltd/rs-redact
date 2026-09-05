# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact` 是面向应用与库作者的策略感知 Rust 脱敏运行时，用于在保留诊断价值的同时避免
泄露机密。它通过同一个有界会话处理被借用的领域对象、JSON、HTTP 值、URI、环境变量和进程
参数，并返回拥有独立文本的脱敏结果。

## 安装

```toml
[dependencies]
qubit-redact = { version = "0.6" }
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
use qubit_redact::Redactor;

#[derive(qubit_redact::Redact)]
#[redact(crate = qubit_redact)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

let login = Login { user: "ada".into(), password: "raw-password".into() };
let output = Redactor::standard().redact(&login);
assert!(!output.text().as_str().contains("raw-password"));
```

调用 `Redactor::standard().redact(&value)`，或用 `Redactor::new(policy)` 构造显式策略。
启用脱敏时，`Complete`、`Truncated`、`Exhausted` 三种状态下的文本都满足保密安全要求；
后两者只表示诊断信息不完整。`Debug`、`Display` 和普通日志可以直接展示
`output.text()`。只有审计、重试或业务逻辑依赖完整性时，才需要检查
`output.summary()`；这类调用方仍可使用 `into_complete_text()` 或降级标记辅助方法。

一批互相独立的诊断值可以只选择一次降级标记，再无需为每个句柄（handle）编写错误处理：

```rust
use qubit_redact::Redactor;

let mut batch = Redactor::standard().batch();
let user = batch.redact_field("user", "ada");
let password = batch.redact_field("password", "raw-password");
let diagnostics = batch.finish_for_diagnostics("<redaction incomplete>");

assert_eq!(diagnostics.text(user).as_str(), "ada");
assert!(!diagnostics.text(password).as_str().contains("raw-password"));
```

未标注的 derive 字段和通过 `unmarked` 写入的值会有意保持不脱敏。字段是否敏感属于下游业务
领域知识，框架既无法可靠推断，也不应要求占绝大多数的普通字段逐一声明“不敏感”。下游
类型应显式标记敏感字段，并在领域模型变化时重新审查。`unmarked` 和 `unredacted` 是显式
跨越信任边界的 API：即使策略为 strict，它们也不会查询运行时字段策略。只能向其传入已经
独立审查、确认可公开的值；不得传入凭据、用户控制的诊断数据，或必须由运行时策略分类的值。
运行时不会修改或擦除源对象。

标量字段 API 接受 `Display`。如果要按值的 `Debug` 表示脱敏，又不希望提前分配字符串或执行
格式化，可传入 `DebugDisplay::new(&value)`。这样，不需要观察原值的 high/secret 不透明掩码
完全不会调用 `Debug`；pass-through、disabled、low、medium 策略仅在实际需要时才格式化。

## 为什么需要这个项目

诊断数据常会在敏感性尚未审查时流入日志、错误上报和技术支持边界。临时掩码方案会让每个调用
点自行决定格式、资源上限和降级方式。本 crate 将这些决定收敛到不可变的策略快照中，在相关输出
之间共享有界预算，并让调用方无需重新格式化源数据即可判断已发布的诊断信息是否完整。

## 能力

- 有界文本、JSON、URI、HTTP、环境变量、argv 和进程渲染；
- 基于 `Sensitivity` 的掩码以及字段、key、路径规则；
- 只报告匹配规则而不输出原始值的检查（inspection）API；
- 借用 `serde_json::Value` 且保持输入不变的解析 JSON API；
- JSON 文本遵循 `qubit-json` 数字边界：负整数装入 `i64`，非负整数装入 `u64`，小数为有限
  `f64`；
- 在一批相关值之间共享预算和摘要的批处理（batch）API；
- 可选的 `serde` 与 derive 集成；默认 feature 集保持最小化。

本 crate 不会推断业务敏感性、不擦除源对象内存，也不会保护未经过本运行时的日志和序列化路径。

禁用策略会有意恢复所有支持入口的原值。这是框架特意保留的进程级调试逃生口，不代表框架
替下游授权。资源限制和控制字符转义仍然生效，但保密脱敏不再生效；授权、调用时机、运行
环境和误用后果由下游负责。派生生成的 `Debug`、`Display`、`Serialize` 实现会有意在每次
调用开始时读取当时的应用默认快照，而不是在值创建时固定策略。因此替换默认值会影响之后的
生成代码调用，包括安装会恢复原值的 disabled 策略。显式创建的 `Redactor`、文本组合器和
批处理对象继续持有创建时的策略快照。

`RedactedText` 表示运行时处理已经结束，展示它时不会再次执行脱敏。该保证取决于所选策略和
显式 writer 选择；若使用了 disabled 策略或不脱敏 writer API，它并不能证明内容仍然保密。

## 延伸阅读

参见 [英文用户手册](doc/user_guide.md)、[中文用户手册](doc/user_guide.zh_CN.md)、
[架构设计](doc/design.zh_CN.md)、
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
