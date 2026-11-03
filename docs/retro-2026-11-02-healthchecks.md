# healthchecks 全量分析复盘（2026-11-02）

目标：用 YASAVulAgent 顺序分析 healthchecks / miniflux-v2 / halo，先跑通 healthchecks。
结果：**4 次运行全部失败**，但修复了 5 个阻塞缺陷、定位了 1 个结构性缺陷。
产出：`covered_file_count = 24 / 657`，`0 findings`（audit 未走完）。

---

## 一、四次运行一览

| # | run id | 时长 | 结局 | 卡点 | tokens (in / out) | 成本@80%命中 |
|---|---|---|---|---|---|---|
| 1 | `022158Z-2bab76b4` | 47 min | failed | `generator didn't stop after athrow()`（MCP） | 12.95M / 0.97M | 13.3 元 |
| 2 | `034814Z-a65e7c9f` | 99 min | failed | `audit.recon: Event loop is closed` | 13.74M / 1.95M | 21.5 元 |
| 3 | `080845Z-6234ad8c` | 9 min | failed | `Invalid IPv6 URL`（init） | ~1.2M / ~0.1M（估） | ~1.3 元 |
| 4 | `082629Z-da0ccbc6` | 195 min | failed | `operations[0].locations ... evidence must be an object` | 18.16M / 2.49M + 3 次 audit 续跑 | 28.4 元 |

合计约 **46.9M tokens ≈ 64.6 元**（DeepSeek 峰值价、80% 缓存命中）；不命中缓存则约 **137.7 元**。

> 注意：run 2 的 `run.json` 现在显示 `step_budget`，那是因为我用 `run_audit` 续跑取栈时覆盖了它；
> 它最初的失败是 `audit.recon failed: Event loop is closed`（见该 run 的 `run.log`）。

四个 run 的失败点全部不同，说明是**一条链上依次暴露**，不是同一个 bug 反复。

---

## 二、已修复的 5 个阻塞问题

### 1. MCP 异步上下文管理器二次 yield（run 1）

- 现象：`RuntimeError: generator didn't stop after athrow()`，吞掉真正的业务异常，audit 只看到一句无信息的报错。
- 根因：`open_yasa_mcp` 里 `except: yield None`，在 `athrow` 之后再次 `yield`。
- 修法：`AsyncExitStack` + `_drain(stack)`；缺失工具检查提到 `yield` 之前；`try: yield session / finally: await _drain(stack)`。
- 文件：`src/yasa_vulnagent/stages/discover/screen/mcp.py`
- 测试：`tests/test_discover_screen_mcp.py`（3 个：消费者异常原样传播、setup 失败 yield None、缺失工具 yield None）
- 验证：之后 48 次 MCP 会话 0 失败，`athrow` 0 次。

### 2. `Event loop is closed`（run 2）

- 现象：audit.recon 第一次模型调用即报 `RuntimeError: Event loop is closed`。
- 根因：`langchain_openai` 有**进程级全局 async httpx client**（`_get_default_async_httpx_client`，绑在首次使用的事件循环上）。流水线每个阶段各自 `asyncio.run`，第二个及以后的循环复用绑定在已关闭循环上的 client。
- 复现（同进程、每次新建 model 实例、连续 3 轮）：

  ```
  round 1: ok
  round 2: FAILED RuntimeError: Event loop is closed
  round 3: ok
  ```

- 修法：`_invoke_model_async` 改为优先 `await asyncio.to_thread(model.invoke, messages)`（同步 client 不绑循环），无 `invoke` 时回落 `ainvoke`。
- 文件：`src/yasa_vulnagent/agent/runtime.py:436`
- 测试：`ModelInvocationLoopTest.test_model_call_survives_a_second_event_loop`
- 验证：run 4 的 recon 连续 63 次模型调用，0 次该错误。

### 3. `Invalid IPv6 URL`（run 3）

- 现象：init.documents 读到第 26/270 个文件时整段失败，9m21s 白费。
- 根因：文档里有 markdown 链接 `[http://localhost:8000](http://localhost:8000)`，`_URL_RE = https?://[^\s<>\"')]+` 不排除 `]`/`(`，吞成 `http://localhost:8000](http://localhost:8000`，`urlparse` 抛 `ValueError`。
- 修法：正则排除 `]`、`(`、反引号；`_normalize_url` 捕获 `ValueError` 返回空串。
- 文件：`src/yasa_vulnagent/stages/init/documents/tools.py:68,721`
- 测试：`test_markdown_link_urls_register_without_raising`（红→绿验证过）
- 验证：真实文档读取成功，登记 `http://localhost:8000`。

### 4. recon 轮次耗尽即崩（run 2 续跑 / run 4 第一次 audit）

- 现象：`audit.recon budget exhausted: step_budget`，20 轮工具调用后一声不响地丢弃全部工作。
- 根因：`RECON_MAX_ROUNDS = 20` 且 `finalize_on_exhaustion=False`；轮次用尽时既不交卷也不保留。
- 修法：轮次 20 → 40；`finalize_on_exhaustion=True`；循环自然结束时把 reason 从 `step_budget` 改为 `round_limit`。
- 文件：`recon/constants.py:17`、`recon/execution.py:139`、`agent/runtime.py:383`
- 测试：`RoundLimitTest.test_exhausted_rounds_report_round_limit`
- 验证：recon 从「22 次调用即崩」变为「63 次调用、4m42s 正常交卷」。

### 5. `historical_references[0].source` 校验（run 4 第二次 audit）

- 现象：`constraints[0].historical_references[0].source must be a non-empty string`，63 次调用的成果被整份丢弃。
- 根因：prompt 里 `historical_references` 只出现空数组 `[]`，从未描述条目结构；模型自造条目 → 校验必拒。
- 修法：prompt 补 `Historical reference shape`（source 必填，commit/path/side/text 可选）+ 规则「无法归因就留空」；校验器对无 source 条目记 warning 后跳过。
- 文件：`recon/prompt.md:59`、`recon/result.py:388`
- 测试：`test_historical_reference_without_source_is_dropped`
- 验证：该关通过，进入下一关（随即暴露问题 6）。

---

## 三、未修复 / 待决策

### 6. `operations.locations` 类型缺失（当前卡点）

模型给出 `locations: ["hc/views.py"]`（字符串数组），校验器要求 Evidence 对象数组
（`{path, start_line, end_line, explanation}`），报 `operations[0].locations[0]: evidence must be an object`。

prompt 与校验器的同类缺口共 4 处（`supporting_evidence`、`counterevidence`、`locations`、`evidence`），
全部只写了 `[]`。建议一次性补齐为 `[Evidence]`，并加一条全局规则。**尚未执行。**

### 7. discover 路由饿死（结构性）

42 分钟窗口内的路由分布：`confirm=43 / review=42 / screen=1`。

- `confirm` 节点三个分支全部返回 `next_action="review"`（`confirm/node.py:753-759`）
- `review` 的 `_route_for_debt` 只要存在任意 `candidate`/`handoff` 债务就回 `confirm`（`review/node.py:189-197`）
- 而 `candidate` 债务 = 所有未确认条目（`ledger.py:919-934`），confirm 每波只清 6 个

因此「未确认 candidate > 0」永远成立时，`screen` 分支**数学上不可达**。
结果：`covered_file_count` 从第 17 分钟起冻结在 24，持续 1h42m，直到 `recursion_limit`。
候选修法：screen 强制插队 / confirm:screen 配比 / 路由改为「覆盖率停滞」触发，均未定。

### 8. documents 预算翻倍的副作用

`DOCUMENTS_DISCOVERY_MAX_MODEL_CALLS: 32 → 128` 让 documents 发现 270 个候选（此前只有几十个）：

- init 耗时 2 min → **32m53s**（documents 30 分钟 `time_budget` 截断）
- init 成本 0.57M → **2.94M tokens**（5 倍）
- 读取预算 `DOCUMENTS_MAX_MODEL_CALLS=96` 在 index≈132 耗尽，其余 138 个文件退化到 map 兜底

收益是 `feature_hit_count=101`（覆盖面更广），代价是 init 成为第二大开销。

### 9. `path is unavailable` 文案误导

run 4 共 10 次。逐条核实：`hc/front/templates`、`hc/web/urls.py`（不存在）属正确拒绝；
但 `hiccup`、`hc/api/tests`、`hc/accounts/templates`、`hc/front/tests` 是**存在但不在任务 scope 内**的目录。
行为正确（scope 外不该搜），文案错误（说成「不可用」让模型以为路径不存在，于是反复换路径重试）。
建议区分「路径不存在」与「超出本任务 scope」。

### 10. 已知 flaky 测试

`test_discover_screen.DiscoverScreenFeatureTest.test_screen_observation_creates_global_candidate_and_confirm_task`
（`len(entries(candidate)) 0 != 1`）。实测：含改动 3/15 失败，`git stash` 掉全部改动后 **2/15 失败** → 既有 flaky，非本轮引入。

### 11. validate 阶段预期仍会 blocked

容器无外网、无 golang 镜像，`validate` 会 `blocked`，`report` 会因 `validation status is not reportable` 失败。
本轮尚未走到该阶段，三个备选方案（修容器 / 让 intake 接受 partial / 从 audit.json 手写 findings）未选定。

---

## 四、贯穿性问题：「一个坏条目毁掉全部工作」

同一形态出现了 4 次：

1. MCP 的 `athrow` 异常被二次 `yield` 吞掉 → 真实错误不可见
2. recon 轮次耗尽直接 raise → 20 轮探索全丢
3. `historical_references` 单条缺 source → 63 次调用全丢
4. `locations` 单条类型错 → 又一次全丢

代码库的校验是「全有或全无」设计。已修 1–3（分别用兜底/交卷/跳过），第 4 个建议同样在 prompt 侧补规格，
校验器只在语义可安全降级处（如缺 source 的引用）做跳过。

---

## 五、当前代码状态

未提交改动（`git status`）：

```
src/yasa_vulnagent/agent/runtime.py
src/yasa_vulnagent/stages/audit/recon/constants.py
src/yasa_vulnagent/stages/audit/recon/execution.py
src/yasa_vulnagent/stages/audit/recon/prompt.md
src/yasa_vulnagent/stages/audit/recon/result.py
src/yasa_vulnagent/stages/discover/confirm/node.py
src/yasa_vulnagent/stages/discover/review/node.py
src/yasa_vulnagent/stages/discover/screen/mcp.py
src/yasa_vulnagent/stages/discover/screen/tools.py
src/yasa_vulnagent/stages/init/documents/tools.py
tests/test_agent_runtime.py
tests/test_audit_recon.py
tests/test_discover_context.py
tests/test_discover_screen_mcp.py
tests/test_discover_tools_bounds.py
tests/test_documents_tools.py
```

测试：**375 passed, 1 skipped**。

---

## 六、建议的下一步（均未执行）

1. **补齐 prompt 的 4 处 Evidence 标注**（成本 0，防下一次 2 元失败）
2. **再续跑一次 audit**（约 2 元，10 分钟）验证 audit 全链能否走到 verify/gate
3. **定 discover 路由修法**，然后做一次干净的全量重跑（约 25 元）
4. **单独处理 validate 的容器依赖**（外网 / golang 镜像）
5. 顺手修 `path is unavailable` 文案 + 那个 flaky 测试
