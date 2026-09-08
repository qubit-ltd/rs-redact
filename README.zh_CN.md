# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact` 帮助应用和库作者为日志、错误报告和技术支持输出建立统一的脱敏边界。
单个字段或 JSON 载荷可直接用内置策略脱敏；需要时可自定义 `RedactionPolicy`；
领域类型也可通过 `#[derive(Redact)]` 生成脱敏的 Debug、Display 与 Serde 输出。
借用视图和 `redact_text()` 不会改变源对象；只有希望对象自身的 Serde 输出也脱敏时，
才需要标注 `#[redact(serde)]`。

## 安装

需要 **Rust 1.94+**。Cargo 包名为 `qubit-redact`，Rust 中以 `qubit_redact` 引入。
标量字段、自定义策略和手写 `Redact` 实现均无需启用可选 feature。

<!-- redact-example: kind=cargo features=none -->
```toml
[dependencies]
qubit-redact = "0.8"
```

| Feature | 作用 |
| --- | --- |
| `derive` | `#[derive(Redact)]`、`#[derive(RedactScalar)]` |
| `serde` | 领域视图的结构化 Serde 适配 |
| `bigdecimal` | BigDecimal 标量支持（包含 `serde`） |
| `json` | JSON 文本与借用的 `serde_json::Value` |
| `http` | URL、请求头、表单、multipart 与 body |
| `uri` | 通用 URI 解析与脱敏 |

下面结构化领域类型的示例需要 derive、Serde 和 JSON：

<!-- redact-example: kind=cargo features=derive,serde,json -->
```toml
[dependencies]
qubit-redact = { version = "0.8", features = ["derive", "serde", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

## 快速开始

认证失败写入日志时，标准策略已把 `password` 等常见字段名识别为 secret，
无需额外配置规则，也无需启用可选 feature。

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;

fn main() {
    let output = Redactor::standard().redact_field("password", "raw-secret");
    assert_eq!(output.text().as_str(), "<redacted>");
}
```

### 脱敏 JSON 载荷

输入本身已是 JSON 时，启用 `json` feature。源 `Value` 不会被修改，只有渲染出的诊断文本会脱敏。

<!-- redact-example: kind=cargo features=json -->
```toml
[dependencies]
qubit-redact = { version = "0.8", features = ["json"] }
serde_json = "1"
```

<!-- redact-example: kind=run features=json -->
```rust
use qubit_redact::Redactor;

fn main() {
    let value = serde_json::json!({"user": "ada", "password": "raw-secret"});
    let output = Redactor::standard().redact_json_value(&value);
    assert!(!output.text().as_str().contains("raw-secret"));
    assert_eq!(value["password"], "raw-secret");
}
```

### 结构化领域类型

使用 `#[redact(serde)]` 后，业务 JSON 与诊断 JSON 都会把密码变成 `<redacted>`；
生成的 Debug 实现也会脱敏普通诊断输出。

<!-- redact-example: kind=run features=derive,serde,json -->
```rust
use qubit_redact::{Redact, Redactor};

#[derive(Redact)]
#[redact(serde, debug)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let login = Login { user: "ada".into(), password: "raw-secret".into() };
    let redactor = Redactor::standard();
    let view = redactor.redact_view(&login);
    assert!(!format!("{view}").contains("raw-secret"));
    assert!(!format!("{login:?}").contains("raw-secret"));
    let json = redactor.to_json(&login).expect("redacted JSON");
    assert_eq!(json, r#"{"user":"ada","password":"<redacted>"}"#);
    assert!(!serde_json::to_string(&login).expect("business JSON").contains("raw-secret"));
    let output = redactor.redact_text(&login);
    assert!(!output.text().as_str().contains("raw-secret"));
}
```

属性与类型支持表见 [derive 说明](derive/README.zh_CN.md)；自定义字段规则、HTTP、URI、
argv/env、batch 与预算等详见用户手册。

## 选择入口

| 需求 | 入口 |
| --- | --- |
| 脱敏单个命名字段 | `redact_field(field, value)` |
| 延迟格式化或序列化，固定策略 | `redact_view(&value)` |
| 立即获取最终文本和完整性摘要 | `redact_text(&value)` |
| 获取紧凑的脱敏 JSON 字符串 | `to_json(&value)` |
| 处理本身就是 JSON 的输入 | `redact_json(text)` / `redact_json_value(&value)` |
| 多个独立值共享一份预算 | `diagnostic_batch()` |
| 拼接一条诊断文本 | `text_composer()` |

## 为什么需要这个项目

字段规则、掩码、格式解析和资源预算可以集中配置，避免每个日志点自行实现。
视图持有策略快照；每次使用都会重新执行，最终文本则可以直接重复展示。

## 核心能力与边界

支持字段和领域对象、JSON、HTTP、URI、环境变量与进程参数，以及规则检查和共享预算。
`RedactScalar` 支持标量 newtype，第三方类型可显式采用 Display 表示。
未标注字段保持普通输出；显式等级由业务类型负责，strict 不覆盖它。
手写领域类型时可使用 `fields.keyed_nested(...)`：业务键公开时，包装内的子结构仍会按自身字段规则脱敏。
disabled 是恢复原值的调试选项；库不擦除源对象，也不保护绕过脱敏入口的输出。

`max_serde_payload_bytes` 限制结构化 Serde 的逻辑标量载荷；`max_output_bytes` 限制库生成的
最终文本或 `to_json()` JSON。两者默认均为 16 KiB，独立配置。直接序列化 view 或派生源对象时，
最终编码长度由调用方 serializer/writer 控制。详见用户手册的预算矩阵。

## 延伸阅读

完整的 feature 配置、属性和类型支持表、策略优先级、HTTP 与 batch 场景见
[中文用户手册](doc/user_guide.zh_CN.md)和[英文用户手册](doc/user_guide.md)。
另见 [derive 说明](derive/README.zh_CN.md)与 [API 文档](https://docs.rs/qubit-redact)。

## 测试

```bash
# 使用默认 feature 集运行测试
cargo test

# 使用项目声明的全部 feature 运行测试
cargo test --all-features

# 格式化并运行完整项目 CI 检查（含 feature 矩阵）
./align-ci.sh
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
