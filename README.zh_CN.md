# Qubit Redact

[![Rust CI](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-sanitize/coverage-badge.json)](https://qubit-ltd.github.io/rs-sanitize/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

面向 Rust 诊断信息、结构化字段、Map、进程参数、环境变量及可选 HTTP 数据的策略化
遮盖库。

## 设计

Qubit Redact 将职责拆成四层：

- `RedactionPolicy` 是字段规则、允许规则、匹配方式和掩码的不可变快照。
- `Redactor` 使用一份策略处理标量字段值和字符串 Map。
- `ArgvRedactor`、`EnvRedactor` 生成有类型且日志安全的进程诊断结果。
- 可选 `http` 模块处理 URL、form、header 和有界 body。

未知字段会原样通过。因此，本库依靠已知结构和已配置字段名，而不是尝试通用地发现
秘密。默认策略提供保守的预定义规则，builder 可增加业务规则和显式允许决策。

## Cargo Feature

默认 feature 集为空，核心 crate 没有外部运行时依赖。

| Feature | 能力 | 可选依赖 |
| --- | --- | --- |
| `derive` | 为具名领域 struct 派生 `Redact` 和 `RedactMut` | `qubit-redact-derive` |
| `serde` | 序列化显式 opt-in 的脱敏视图 | `serde` |
| `http` | URL、form、header 和有界 body 遮盖 | `form_urlencoded`、`http`、`serde_json`、`url` |

```toml
[dependencies]
# 仅在需要 HTTP 能力的 crate 中启用：
# cargo add qubit-redact --features http
# cargo add http@1.4
qubit-redact = { version = "0.1", features = ["http"] }
http = "1.4"
```

仅需要无依赖 core 时，改用 `qubit-redact = "0.1"`。

## 标量与 Map

```rust
use std::collections::HashMap;

use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .build()?;
    let source = HashMap::from([
        ("tenant_secret".to_owned(), "raw".to_owned()),
        ("display_name".to_owned(), "Alice".to_owned()),
    ]);
    let redacted = Redactor::new(policy).redact_map(&source);
    assert_eq!(redacted["tenant_secret"], "<redacted>");
    assert_eq!(source["tenant_secret"], "raw");
    Ok(())
}
```

`redact_map_in_place` 提供对应的原地修改操作。两个 Map 方法都根据 key 分类 value，
并保留安全值。

## 策略配置

```rust
use qubit_redact::{
    FieldNameMatching, MaskPolicy, RedactionPolicy, Redactor, Sensitivity,
};

fn main() {
    let policy = RedactionPolicy::builder()
        .matching(FieldNameMatching::ExactOrTokenSuffix)
        .raise("license_key", Sensitivity::High)
        .allow_exact("public_token")
        .mask(Sensitivity::High, MaskPolicy::fixed("[hidden]"))
        .build()
        .expect("the policy is valid");

    RedactionPolicy::set_global_default(policy.clone())
        .expect("the application installs its default only once");
    let inherited = RedactionPolicy::builder()
        .build()
        .expect("the default snapshot remains valid");
    assert_eq!(inherited.sensitivity_for("license_key"), Some(Sensitivity::High));

    let redactor = Redactor::new(policy);
    assert_eq!(redactor.redact("LICENSE_KEY", "abcdef").as_str(), "[hidden]");
}
```

`raise` 不会削弱已有规则。只有明确需要替换（包括降级）时才使用
`override_level`。精确允许规则只作用于完整的规范化字段。后缀允许规则还可能允许
`request_public_token` 这样的带前缀字段，披露范围更广；只有审查并接受该风险后才应
使用。

`RedactionPolicy::default()` 读取当前进程级默认策略的快照。
`RedactionPolicy::set_global_default(policy)` 只能成功设置一次；后续调用返回
`GlobalDefaultAlreadySet`，且不会替换已有默认值。`RedactionPolicy::builder()` 从调用时的
默认值快照开始构建。此前创建的 policy、builder 和 redactor 都不会随之变化。

## 领域对象

启用 `derive` 后，可在字段边界声明脱敏语义。没有属性的字段保持普通值；递归处理和
Map 按 key 分类都必须显式指定。

```rust
use std::collections::HashMap;

use qubit_redact::{Redact, RedactionPolicy, Sensitivity};

#[derive(Redact)]
struct Account {
    id: u64,
    #[redact(level = "secret")]
    password: String,
    #[redact(map)]
    metadata: HashMap<String, String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::empty_builder()
        .raise("api_key", Sensitivity::Secret)
        .build()?;
    let account = Account {
        id: 1,
        password: "raw-password".to_owned(),
        metadata: HashMap::from([
            ("api_key".to_owned(), "raw-key".to_owned()),
        ]),
    };
    let output = format!("{:?}", account.redacted_with(&policy));
    assert!(!output.contains("raw-password"));
    assert!(!output.contains("raw-key"));
    Ok(())
}
```

字段类型实现了 `Redact` 时，仍然只有标记 `#[redact(nested)]` 才会递归处理；没有该
属性就绝不隐式遍历。`#[redact(skip)]` 会从脱敏后的 Debug、Display 和 serde 表示中省略
字段，但不会删除或修改原对象字段，`RedactMut` 也不会改它。

`RedactMut` 是独立且显式的破坏式契约。`redact_in_place`、`into_redacted` 和基于 clone
的 `to_redacted` 支持相同的 `level`、`nested`、`map` 字段模式。`to_redacted` 会短暂产生
第二份原始敏感数据；高敏感场景应优先使用 `redact_in_place` 或 `into_redacted`。

同时启用 `derive`、`serde`，再给具名 struct 添加 `#[redact(serde)]`，即可序列化其脱敏
视图。原类型自身的 `Serialize`、`Debug`、`Display` 行为不变，`Redacted` 不实现
`Deserialize`。

```rust
use qubit_redact::Redact;

#[derive(Redact)]
#[redact(serde)]
struct Credentials {
    #[redact(level = "secret")]
    token: String,
    #[redact(skip)]
    internal_note: String,
}

let value = Credentials {
    token: "raw-token".to_owned(),
    internal_note: "not serialized".to_owned(),
};
let json = serde_json::to_string(&value.redacted()).unwrap();
assert!(!json.contains("raw-token"));
assert!(!json.contains("internal_note"));
```

`redacted()` 会快照进程级默认策略；`redacted_with` 会快照显式策略，所有 nested 和 Map
字段都沿用同一快照。第一版不支持字段级 Map policy；字段需要不同策略边界时，请使用
领域 newtype 并通过 `nested` 处理。derive 当前只支持具名 struct。

## 进程诊断

`ArgvRedactor::redact_items` 信任调用方提供的敏感等级，不推断命令行语法。
`redact_heuristically` 会额外识别常见 option 和赋值形式，但不会把 shell payload 当作
脚本解析。

`EnvRedactor` 处理 UTF-8 pair；任一操作系统组件不是合法 UTF-8 时会安全关闭。结果可
安全显示为 `NAME=VALUE`。
自定义 `Debug` 实现需要隐藏捕获值时，可使用 `redacted_debug` 固定输出
`<redacted>`；该 wrapper 绝不会调用被包装值自身的 `Debug` 实现。

```rust
use std::ffi::OsStr;

use qubit_redact::{ArgvRedactor, EnvRedactor, argv::ArgvItem};

fn main() {
    let items = [
        ArgvItem::plain(OsStr::new("client")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("secret")),
    ];
    let output = ArgvRedactor::default().redact_heuristically(items);
    assert!(!output.to_string().contains("secret"));

    let environment = EnvRedactor::default().redact_pair("PASSWORD", "secret");
    assert_eq!(environment.to_string(), "PASSWORD=<redacted>");

    let captured_bytes = b"secret output";
    assert_eq!(
        format!("{:?}", qubit_redact::redacted_debug(captured_bytes)),
        "<redacted>",
    );

    let log_safe = qubit_redact::Redactor::default()
        .redact("message", "line one\nline two")
        .escape_for_log();
    assert_eq!(log_safe.to_string(), "line one\\nline two");
}
```

`RedactedText` 刻意不实现 `Display`：值遮盖和日志转义是两种不同保证。把标量结果写入
纯文本日志前，必须显式调用 `escape_for_log()`。argv 和 env 的结果类型已经跨过该边界，
可安全地使用 `Display`。

## HTTP 遮盖

通过 `cargo add qubit-redact --features http` 启用 `http`，并通过
`cargo add http@1.4` 添加示例直接使用的 `http` 依赖（或使用上面的等价 Cargo.toml
配置）。`HttpRedactor` 持有不可变 `HttpRedactionPolicy`，提供 URL、
URL-encoded form、header 和 body 操作。`BodyCapture` 区分完整输入和受检的截断输入，
`BodyBudget` 同时限制解析输入和渲染输出。

不合法或已截断的结构化 body 会安全关闭。不透明文本、无 key 的 JSON 标量、文件
part、匿名 multipart part 和 URL path 默认采用保守策略。HTTP 结果类型只暴露日志
安全文本，不提供原始 body 逃生口。

```rust
use http::HeaderValue;
use qubit_redact::http::{BodyCapture, BodyRedaction, HttpRedactor};

fn main() {
    let body = br#"{"password":"secret","mode":"debug"}"#;
    let content_type = HeaderValue::from_static("application/json");
    let result: BodyRedaction = HttpRedactor::default()
        .redact_body(BodyCapture::complete(body), Some(&content_type));
    let display_text = format!("{result}");
    assert!(!display_text.contains("secret"));
}
```

HTTP 遮盖只接受调用方提供的有界 capture，不会自行读取或缓存网络 body。
`BodyRedaction` 的 `Display` 实现就是安全日志边界，并且会保持配置的输出预算。

`TextBodyPolicy::PassThrough`、`UnkeyedJsonValuePolicy::PassThrough` 和
`UrlPathPolicy::Preserve` 都是显式诊断 opt-in。只有应用已经接受相应信息披露风险时才
应选择它们。

## 安全边界

- 字段名会被规范化，可选择精确或 token 后缀匹配。
- 允许规则会有意胜出并可能暴露数据，应把它们作为安全策略审查。
- 本库不会发现保存在未知字段名下的秘密。
- `RedactedText` 表示字段值已按策略处理；`LogSafeText` 还会转义控制字符和 Unicode
  行序字符。
- 应把有类型的显示结果作为日志边界，不要再用原始输入拼接字符串。

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

仓库地址：[https://github.com/qubit-ltd/rs-sanitize](https://github.com/qubit-ltd/rs-sanitize)
