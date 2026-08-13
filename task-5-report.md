# Task 5 fixture 修复报告

- 将 fixture 中误写入 raw string 的反斜杠移除，使标量生成 JSON token `"raw-unkeyed-secret"`，并使请求体生成 `{"items":[...]}`。
- 已确认测试源文件不含 `\\\"raw-unkeyed-secret`。
- 指定测试已运行；fixture 修正后失败，`allocation_count` 为 283，触发每个标量分配完整 marker 的断言。
- 根因定位显示，同一合法 body 仅由 `serde_json::from_slice::<Value>` 解析就产生 265 次 allocation；完整 HTTP 脱敏为 283 次，其中绝大多数是输入字符串 materialize，而不是 marker 分配。
- `JsonRedactionState` 已在第一个无法取得 marker 时返回全局 `JsonRedactionStop`；HTTP 收到 `mask_exhausted` 后继续精确映射为 `<truncated>`，因此不改生产 stop 路径。
- allocation 回归改为先测同一合法 body 的 parser-only baseline，再限制完整 HTTP 脱敏最多增加 32 次 allocation，并保留 `<truncated>`、truncated 状态和不泄漏断言。
- 已临时注入 256 次 marker 字符串分配验证断言灵敏度：parser baseline 为 265、完整测量为 539，增量阈值按预期失败；注入随后撤销。
- focused allocation test、完整 `http_allocation_tests`（4 tests）和 HTTP JSON focused tests（15 tests）均通过。
