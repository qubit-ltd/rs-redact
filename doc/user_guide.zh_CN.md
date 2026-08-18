# 用户指南

使用 `Redactor::standard()` 开始一次 direct 操作：

```rust
use qubit_redact::Redactor;
let output = Redactor::standard().redact_field("token", "raw-token");
assert_eq!(output.as_str(), "****");
```

需要一次发布多个诊断值时，将具名结果暂存到 `RedactionSession` 并调用 `finish`；发布是
原子的，每个 adapter 只消费自己的有限输入。

JSON 使用策略中的 `JsonValueLimits`；HTTP 使用 `BodyCapture` 元数据并在解析失败时
fail-closed；URI 结果提供组件和原因元数据。上述路径都不使用策略级共享输入/输出字节预算。

领域实现应通过 `RedactionWriter` 写入；派生结构体、Map 和嵌套 JSON 使用独立的结构上下文。
