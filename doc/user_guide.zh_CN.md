# qubit-redact 用户手册

[README](../README.zh_CN.md) · [English User Guide](user_guide.md) · [设计文档](design.zh_CN.md) · [Derive Guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.zh_CN.md)

## 手册目标与读者

本手册面向使用 `qubit-redact` 0.5 构建日志与诊断边界的应用和库作者。适用于值可能进入
日志、错误信息或技术支持工具，且应用必须自行判断字段敏感性的场景。它不保护绕过运行时的输出，
也不会擦除源对象内存。

## 概念模型

`Redactor` 持有不可变策略快照。composer 或 batch 会开启一次有界渲染事务，发布拥有独立内容
的文本和摘要：

```text
被借用的值 -> 策略判定 + 事务预算
              -> composer：RedactionTextOutput
              -> batch：handles + RedactionBatchOutput
              -> inspection：RedactionInspectionResult
```

单值便利方法和 composer 返回 `RedactionTextOutput`；batch 通过 `RedactionBatchOutput` 发布
可独立解析的 item，inspection 返回不渲染文本的 `RedactionInspectionResult`。每个已渲染 item
都携带安全文本和 `RedactionSummary`。启用脱敏时，
`Complete`、`Truncated`、`Exhausted` 三种状态下发布的文本都满足保密安全要求。后两种
状态表示诊断信息不完整，不表示源数据已经泄露。因此 `Debug`、`Display` 和普通诊断日志
可以直接使用 `output.text()`；强制这些调用方逐一分析原因，也不会产生可执行的恢复动作。

只有审计、重试、业务判断或结构化输出契约依赖完整性时，才检查 `completion()` 和
`reasons()`。这类调用方可以用 `complete_text()` / `into_complete_text()` 拒绝不完整结果，
或用 `text_or_marker()` / `into_text_or_marker()` 选择展示降级标记。`Truncated` 保留安全的
已接纳表示，`Exhausted` 表示共享预算无法容纳完整替代；原因集合可说明 JSON、form、
multipart 等解析降级和预算限制。

## 贯穿场景：发布不含密码的登录诊断信息

认证服务需要在一条诊断事件中记录用户名和含密码的请求字段：用户名应保留，密码不能出现在输出中，
预算不足时还要使用统一的降级标记。batch 会让这组值共享同一份策略和预算：

```rust
use qubit_redact::Redactor;

let mut batch = Redactor::standard().batch();
let user = batch.redact_field("user", "ada");
let password = batch.redact_field("password", "raw-password");
let output = batch.finish_for_diagnostics("<redaction incomplete>");

assert_eq!(output.text(user).as_str(), "ada");
assert!(!output.text(password).as_str().contains("raw-password"));
```

`finish_for_diagnostics()` 会把不完整 item、无效 item 和其他 batch 的 handle 都映射成同一个
已转义 marker，不返回 `Result`。确实需要区分这些程序错误的调用方仍使用严格路径：
`finish()` 加 `RedactionBatchOutput::resolve()`。

## 安装与最小配置

加入依赖后，只启用应用实际使用的集成能力：

```toml
[dependencies]
qubit-redact = { version = "0.5" }
```

默认 feature 集为空。使用 `#[derive(Redact)]` 时启用 `derive`；派生字段使用生成的序列化
适配器时还要启用 `serde`。直接使用脱敏序列化也需要 `serde`；只有处理相应输入格式时才启用
`json`、`http` 或 `uri`。

## 核心工作流

### 渲染领域值

实现小型运行时 trait，或在下游 crate 中使用 derive：

```rust
use qubit_redact::{Redact, RedactionWriter, Redactor, Sensitivity};

struct Login { user: String, password: String }

impl Redact for Login {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Login", |fields| {
            fields.unmarked("user", || self.user.as_str());
            fields.sensitive(Sensitivity::Secret, "password", || self.password.as_str());
        });
    }
}

let login = Login { user: "ada".into(), password: "raw".into() };
let output = Redactor::standard().redact(&login);
assert!(!output.text().as_str().contains("raw"));
assert_eq!(login.password, "raw");
```

子系统需要显式策略时使用 `Redactor::new(policy)`。运行时没有可变脱敏 API，也不提供内存擦除。

### 选择字段写入方式

`RedactionWriter` 提供显式字段决策：

- `unmarked(name, access)` 输出经过审查的普通值；
- `sensitive(level, name, access)` 应用敏感等级掩码；
- `nested(name, value)` 委托给另一个 `Redact` 实现；
- `map(name, value)` 对支持的 Map 按 key 处理；
- `keyed_value(name, key, value)` 使用兄弟运行时 key 对单个字段值分类，
  语义与一条 Map entry 相同；
- `json(name, value)` 递归处理 JSON；
- `skipped(name, access)` 省略字段且不渲染其值。

每个操作都参与同一个输出预算和摘要。未标注字段会有意保持原样，因为敏感性属于下游业务
领域知识，通用框架无法从 Rust 类型、字段名或当前内容中可靠推断。现实中普通字段占绝大
多数，要求它们逐一声明“不敏感”只会增加噪声，并不会增加有效知识。下游必须显式标记可能
包含敏感数据的字段，并在领域模型变化时重新审查；strict policy 和 inspection 都不会覆盖
这个领域决策。

标量字段 API 接受惰性的 `Display` 值。运行时先判定敏感等级，再决定是否格式化；因此
`High` 和 `Secret` 字段不会触发格式化。只有 `Debug` 的值可以借助 `format_args!`：

```rust
use std::fmt;

use qubit_redact::Redactor;

struct Request;

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("reviewed-debug-view")
    }
}

let request = Request;
let output = Redactor::strict().redact_field(
    "request",
    &format_args!("{request:?}"),
);
assert!(!output.text().as_str().is_empty());
```

### 渲染其他格式

运行时为 JSON 文本和值、URI、HTTP header/query、环境变量、argv 和进程描述提供有界脱敏。
每种格式保留自身解析和转义规则，同时共享策略决策和事务预算。

解析 JSON 时输入只被借用且保持不变：

```rust
use qubit_redact::Redactor;

let value = serde_json::json!({"password": "raw", "visible": "shown"});
let output = Redactor::standard().redact_json_value(&value);
let inspection = Redactor::standard().inspect_json_value(&value);
assert!(!output.text().as_str().contains("raw"));
assert_eq!(value["password"], "raw");
let _ = inspection;
```

`RedactionBatch::redact_json_value` 以及其他 batch 方法会共享预算，并发布可解析为最终文本
和摘要的 handle。

JSON 文本只解析一次，解析过程同时完成结构准入并构造 admitted tree。非法 JSON 或遍历
超限时会整体 fail-closed。借用 `Value` 的路径不会 clone、转成字符串或修改调用方对象；
领域实现可用 `fields.json_value("payload", &value)` 写入不带额外字符串引号的 JSON 值。
序列实现则应逐项调用 `items.json_value_item(&value)`，它会执行同样的递归 JSON 策略。对于
声明数据类型为 JSON 的下游集合，这一点尤其重要：每一项都必须按 JSON 结构遍历，不能作为
不透明标量格式化。

```rust
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct Documents(Vec<serde_json::Value>);

impl Redact for Documents {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.sequence(|items| {
            for value in &self.0 {
                items.json_value_item(value);
            }
        });
    }
}
```

JSON 文本采用 `qubit-json` 的明确数字契约：负整数必须装入 `i64`，非负整数必须装入 `u64`，
小数/指数必须得到有限 `f64`。越界文本沿用 fail-closed 的无效 JSON 路径；serde_json 旧私有
Number marker key 是普通 object key。

## 进阶用法

### 检查决策与控制策略

Inspection 会报告规则匹配、敏感度和完成状态，但不会发布原始值。它适合在确定日志或序列化
边界前解释某字段为何会被掩码。

`RedactionPolicy::disabled()` 是显式关闭保密脱敏的选项，也是框架有意保留的进程级调试
逃生口。字段、JSON、URI、HTTP、环境变量、argv、进程、derive 字段模式和生成的 Serde
输出都会恢复原值，但仍受运行时资源上限约束。控制字符转义也仍然生效，但这两项机制都不
表示结果已经脱敏。框架只负责执行所选策略；是否有权禁用、在哪个环境和时机禁用，以及误用
后果都由下游负责。让不可信请求控制该开关通常是不安全的，但阻止下游故意或错误调用 API
不属于框架保证。

```rust
use qubit_redact::{RedactionPolicy, Redactor};

let mut policy = RedactionPolicy::disabled();
assert!(policy.is_disabled());
policy.set_disabled(false);
let output = Redactor::new(policy).redact_field("password", "raw-secret");
assert!(!output.summary().is_redaction_disabled());
assert!(!output.text().as_str().contains("raw-secret"));
```

策略启用时，`Complete`、`Truncated` 和 `Exhausted` 文本都应保持保密安全。只有调用方
关心完整性、审计原因或重试决策时才检查 `summary().completion()` 与
`summary().reasons()`，不要解析 `<truncated>` 等文本标记推断状态。若 inspection 用于
安全决策，任何 inspection error 都表示分类不完整，应按敏感处理。

`Redactor::replace_application_default()` 影响之后调用 `application_default()` 取得的对象，
以及每次重新获取快照的生成格式化代码。已经创建的 `Redactor`、composer 和 batch 继续
持有原有不可变快照；替换不会追溯切换正在进行的工作。

## 错误与诊断

当调用方需要区分完整结果与预算或解析降级时，检查 `summary().completion()`、
`summary().reasons()` 和 `summary().usage()`；不要解析展示文本来推断状态。严格的展示路径可用
`complete_text()` 和 `into_complete_text()` 拒绝不完整结果；诊断展示可用 `text_or_marker()` 和
`into_text_or_marker()` 选择明确的降级标记。若 inspection 结果用于安全判断，任何 inspection
error 都意味着分类不完整，应按敏感结果处理。

## 排障

- 发现原值时，先检查 `output.summary().is_redaction_disabled()` 以及创建 composer 或
  batch 时采用的策略快照。
- 出现非预期截断时，检查 `completion()`、`reasons()` 和 `usage()`；同一事务内的操作
  会有意共享资源上限。
- 字段未命中时，核对字段名并复查所有未标注字段；运行时不会推断业务敏感度。

## 限制与最佳实践

- 应依据业务领域知识标记敏感字段；`unmarked` 和未标注的 derive 字段会有意保持可见。
- 不要将 `RedactionPolicy::disabled()` 暴露给请求控制的输入；它会恢复原值，只适合作为进程级
  调试逃生口。
- 本 crate 只保护经过其运行时的调用，不擦除源对象内存，也不保护无关日志或序列化路径。

## 延伸阅读

参见 [README](../README.zh_CN.md)、[English User Guide](user_guide.md)、
[API 文档](https://docs.rs/qubit-redact)和
[derive 手册](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.zh_CN.md)。

验证本地检出内容可运行：

```bash
cargo test --all-features
./align-ci.sh
./ci-check.sh
```


## 许可证

Apache-2.0，详见 [LICENSE](../LICENSE)。
