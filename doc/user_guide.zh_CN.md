# qubit-redact 用户手册

[README](../README.zh_CN.md) · [English User Guide](user_guide.md) · [Derive Guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.zh_CN.md)

`qubit-redact` 在不修改源对象的前提下生成有界、策略感知的输出。`Redactor` 持有策略快照，
一次脱敏操作拥有最终的 `RedactedText`。

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
位置会掩码，就省略其字段决策。

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

## 4. Inspection 与禁用策略

Inspection 会报告规则匹配、敏感度和完成状态，但不会发布原始值。它适合在确定日志或序列化
边界前解释某字段为何会被掩码。

`RedactionPolicy::disabled()` 是显式退出选项，会保留原始渲染值；调用方必须把它限制在经过审查的本地边界内。

## 5. 验证

```bash
cargo test --all-features
./align-ci.sh
./ci-check.sh
```

字段属性和生成实现参见 [derive 手册](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.zh_CN.md)。

## 许可证

Apache-2.0，详见 [LICENSE](../LICENSE)。
