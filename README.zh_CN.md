# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact` 用于把字段、Rust 领域对象、命令数据、JSON、HTTP 和 URI 组合成有资源上限、
可安全写入日志的诊断信息。它适合需要为整条事件统一决定脱敏规则、预算和发布时机的应用，
而不是让每个待记录的值各自处理这些问题。

## 安装

按需启用格式集成：

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["http", "json", "uri"] }
```

最低支持 Rust 1.94。`serde`、`json`、`http` 与 `uri` 是可选 feature；字段、领域对象、
argv、环境变量和进程数据在默认 feature 集中即可使用。

## 快速开始

某个 API 客户端需要记录失败原因，同时将脱敏后的 URL 交给结构化遥测。access token 绝不能
出现在发布的文本中，而且两份结果必须共用同一组资源上限。先构建不可变 policy，再让一个
session 承担这一轮事件：

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

`finish()` 是发布边界：它返回聚合文本、当前 transaction 的摘要和单项结果。
`RedactionHandle` 是不透明句柄，只能使用创建它的那份 `RedactionSessionOutput` 解析。随后，
同一个 session 可按原 policy 快照立即处理下一条事件。

## 为什么需要这个项目

分别调用各类格式化工具看似容易组合，却容易造成策略不一致：URL 与响应 body 可能使用不同
规则，各自绕过总输出预算；在回调失败前，半成品也可能已经泄露。`RedactionSession` 会在
组装期间私有保存整条事件。聚合 API 和单项 API 共用同一份策略和 transaction 预算，只有
`finish()` 才会原子发布完成结果。用户编写的脱敏逻辑发生 panic 时，当前 transaction 会被
丢弃，随后继续展开 panic。

## 核心能力

- 提供不可变 `RedactionPolicy` 快照，以及确定性的 `standard()` 和默认安全关闭的
  `strict()` policy。
- 以事务方式配置字段规则、掩码、资源上限和已启用的 HTTP/URI/JSON 行为。
- argv、环境变量、进程、JSON、HTTP、URI 均支持聚合文本和可单独解析的单项结果。
- 通过 `Redact` 与 `RedactionWriter` 显式渲染领域对象。
- 通过 `RedactionSummary` 提供可供程序读取的完成状态、原因和资源用量。
- 输出保持 UTF-8 与日志安全；遇到输入、输出或结构上限时会安全降级。

本库不会从任意值内容中猜测秘密信息。新增业务字段时应逐一审查并明确标注。`unredacted`
是信任边界，不是图省事的旁路，只能接收已经独立确认可公开的数据。资源上限约束的是整条
诊断事件，不是彼此独立的格式配额。

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
