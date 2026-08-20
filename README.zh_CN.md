# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact` 用来构建有资源上限、适合写入日志的脱敏诊断信息。它让标量字段、领域对象、
命令数据、JSON、HTTP 与 URI 共用同一份策略快照、预算和发布边界，适合需要组合多类数据
但又不能接受局部脱敏失控的 Rust 应用。

## 安装

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["http", "json", "uri"] }
```

最低 Rust 版本为 1.94。`serde`、`json`、`http`、`uri` feature 分别启用对应集成；
argv、env、process、字段和领域 writer 不依赖可选 feature。

## 快速开始

假设 HTTP 客户端失败时既要拼出一段诊断文本，又要把脱敏 URL 单独交给结构化遥测。
可复用 session 会让两份结果共用一轮 transaction 的资源上限，并且在 `finish()` 前
不会发布 handle 对应的文本：

```rust
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

let policy = RedactionPolicy::builder()
    .fields(|fields| {
        fields.secret_sensitive("access_token");
    })?
    .limits(|limits| {
        limits.max_input_bytes(64 * 1024).max_output_bytes(16 * 1024);
    })?
    .build()?;

let mut session = Redactor::new(policy).session();
let url = session.redact_http_url(
    "https://api.example.test/users?access_token=raw-secret",
);
session.literal("request failed: ").field("request_id", "req-42");

let output = session.finish();
let safe_url = output.resolve(url)?;
assert!(!output.text().as_str().contains("raw-secret"));
assert!(!safe_url.text().as_str().contains("raw-secret"));

# Ok::<(), Box<dyn std::error::Error>>(())
```

同一个 session 可以立刻开始下一轮 transaction。handle 只能由创建它的那轮
`RedactionSessionOutput` 解析。

## 为什么需要这个项目

如果日志工具分别处理每个值，各项可能看到不同的策略快照，组合结果也可能绕过总输出
上限；用户回调发生 panic 时，还可能留下部分结果。`RedactionSession` 把一轮诊断所需的
状态全部私有暂存。`finish()` 一次性发布聚合文本、单项结果和机器可读的
`RedactionSummary`，随后自动重置 session。用户脱敏代码 panic 时，当前 transaction
会整体回滚，panic 继续向外传播。

## 核心能力

- 提供确定性的 `standard()`、`strict()`，以及供 `Redact::redacted()` 使用的原子化
  应用默认快照。
- 字段规则、资源限制、HTTP 和 URI 配置都通过事务式 policy namespace 构建。
- argv、env、process、JSON、HTTP、URI 同时提供聚合 API 和不透明 handle API，
  并共用 transaction runtime。
- 通过 `Redact` 与 `RedactionWriter` 显式描述领域对象，同时记录完成状态、原因和资源
  用量。
- 最终输出保持 UTF-8 与日志安全。预算耗尽或格式非法时安全降级，由 summary 报告，
  `finish()` 本身不返回错误。

本库不会根据任意值内容猜测敏感性。业务类型新增字段后必须审查标注。
`RedactionWriter::unredacted` 是明确的信任边界，不能传入秘密数据。动态 map 使用
`RedactionFields::map` 时，每个 entry 都会按自己的 key 走当前 policy 分类。

## 从旧 API 迁移

| 已移除概念 | 事务式替代方案 |
| --- | --- |
| `RedactionConfig` 与可变 edit view | `RedactionPolicy::builder()` namespace |
| 各格式独立 redactor facade | `Redactor::redact_*` 或 session format API |
| lazy/display result wrapper | `finish()` 后的 `RedactionOutput` |
| keyed session result | 不透明 `RedactionHandle` 与 `output.resolve(handle)` |
| 用 session error 表示安全降级 | `RedactionSummary` 的完成状态、原因和用量 |

项目不提供 deprecated alias 或兼容模块。

## 延伸阅读

- [中文用户指南](doc/user_guide.zh_CN.md)
- [English user guide](doc/user_guide.md)
- [API 文档](https://docs.rs/qubit-redact)
- [事务式架构设计](doc/2026-08-19-rs-redact-transactional-redesign-design.md)

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
