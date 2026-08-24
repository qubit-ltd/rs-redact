# qubit-redact 用户手册

[README](../README.zh_CN.md) · [English User Guide](user_guide.md) · [Derive Guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.zh_CN.md)

本手册面向使用 `qubit-redact` 0.5 构建日志与诊断边界的应用和库作者。运行时不会修改
源对象：`Redactor` 持有不可变策略快照，每个 composer 或 batch 独占一份预算，只发布
最终文本与摘要。

## completion 是结果的一部分

每个渲染入口都会返回 `RedactionTextOutput`：安全文本和 `RedactionSummary`。只有
`Complete` 的结果可以用 `into_complete_text()` 取走文本；`Truncated` 或 `Exhausted`
会返回摘要，调用方必须决定本地展示策略。需要明确的降级标记时，使用
`into_text_or_marker("<redaction incomplete>")`，不要静默把部分 URL、请求头或命令描述
当作完整信息展示。
输出需要保持借用时，可使用 `complete_text()` 或
`text_or_marker("<redaction incomplete>")`。batch 调用方可以用这两个借用式方法对每个
已解析 item 独立应用相同规则。

`Truncated` 至少保留了非空的安全替代文本；`Exhausted` 表示共享输出预算无法容纳完整替代。
`reasons()` 可说明 JSON、form、multipart 等解析降级及预算原因。

## 1. 渲染领域值

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

## 2. Writer scope

`RedactionWriter` 提供显式字段决策：

- `unmarked(name, access)` 输出经过审查的普通值；
- `sensitive(level, name, access)` 应用敏感等级掩码；
- `nested(name, value)` 委托给另一个 `Redact` 实现；
- `map(name, value)` 对支持的 Map 按 key 处理；
- `json(name, value)` 递归处理 JSON；
- `skipped(name, access)` 省略字段且不渲染其值。

每个操作都参与同一个输出预算和摘要。可能包含敏感数据的字段不能因为当前策略在其他
位置会掩码，就省略其字段决策。未标注字段是永久由下游承担的信任决定；strict policy 和
inspection 都不会推断或提升其敏感度。

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

## 3. 其他格式

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

## 4. Inspection 与禁用策略

Inspection 会报告规则匹配、敏感度和完成状态，但不会发布原始值。它适合在确定日志或序列化
边界前解释某字段为何会被掩码。

`RedactionPolicy::disabled()` 是显式关闭保密脱敏的选项。字段、JSON、URI、HTTP、环境变量、argv、
进程、derive 字段模式和生成的 Serde 输出都会恢复原值，但仍受运行时资源上限约束。
控制字符转义也仍然生效，但这两项机制都不表示结果已经脱敏。只能通过经过审查的启动配置
启用它，不能让不可信请求动态切换。

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

## 5. 排障与限制

- 发现原值时，先检查 `output.summary().is_redaction_disabled()` 以及创建 composer 或
  batch 时采用的策略快照。
- 出现非预期截断时，检查 `completion()`、`reasons()` 和 `usage()`；同一事务内的操作
  会有意共享资源上限。
- 字段未命中时，核对字段名并复查所有未标注字段；运行时不会推断业务敏感度。
- 本 crate 只保护经过其运行时的调用，不擦除源对象内存，也不保护无关日志或序列化路径。

## 6. 验证

```bash
cargo test --all-features
./align-ci.sh
./ci-check.sh
```

字段属性和生成实现参见 [derive 手册](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.zh_CN.md)。

## 许可证

Apache-2.0，详见 [LICENSE](../LICENSE)。
