# 分析目标（targets/）

这里纳管 3 个真实开源 Web 项目，作为 YASAVulAgent 的漏洞发现 / 验证 / 报告链路分析对象。
选型指标是 2026-11-02 的实测快照，机器可读版本在 [`registry.json`](registry.json)。

## 一览

| id | 仓库 | 语言 / 栈 | 仓库体积\*\* | YASA 源文件 | 安全治理 | 维护者回复\* | Docker |
|---|---|---|---|---|---|---|---|
| `healthchecks` | [healthchecks/healthchecks](https://github.com/healthchecks/healthchecks) | Python / Django | 26MB | 657 `.py` + 42 `.js` | SECURITY.md；1 条 advisory（2023-01） | 65% / 1.9h | `docker/Dockerfile` + compose |
| `miniflux-v2` | [miniflux/v2](https://github.com/miniflux/v2) | Go / net/http | 39MB | 441 `.go` | SECURITY.md；6 条 advisory（最新 2026-06）；Dependabot + CodeQL | 15% / 9.8h | 仅 devcontainer + Debian 打包 |
| `halo` | [halo-dev/halo](https://github.com/halo-dev/halo) | Java / Spring Boot | 87MB | 1383 `.java` + 890 `.ts` | SECURITY.md；6 条 advisory（最新 2026-10-21） | 30% / 4.6h | 根 `Dockerfile` |

\* 口径：最近 20 条 issue 中，前 3 条评论里由 `MEMBER/OWNER/COLLABORATOR` 回复的比例，以及首次维护者回复的中位延迟。用于横向对比，不是 SLA。

\*\* GitHub API 的 `diskUsage`（含历史）。实际 checkout 体积是 9.5MB / 4.8MB / 17.4MB，`.git` 分别是 27MB / 40MB / 92MB，可用 `python3 scripts/fetch_targets.py` 复核。

## 为什么是这三个

- **覆盖 YASA 支持的后端语言**。`yasa_mcp` 的 `support_languages` 为 Java / Python / JavaScript / Go / PHP（见 `tools/yasa-mcp/src/yasa_mcp/config/global_config.py`），这三个目标正好覆盖 Python、Go、Java 三种独立栈。
- **体量可被 YASA 预处理**。26 / 39 / 87MB，在 `YASA_INIT_TIMEOUT=3600` 秒内可完成 init。已排除 445MB（directus）、1.5GB（nocodb）、391MB（librenms）、24k 个 TS 文件的 n8n。
- **有安全治理痕迹**。三者都有 `SECURITY.md` 与已披露的 GitHub security advisory 历史，`report` 阶段默认的 GitHub-advisory 形状路由有落点。
- **近期在维护**。三者最近推送都在 2026-10/11；已排除 2024-06 后停更的 `OWASP/NodeGoat`、0 条 advisory 的 `apache/shiro`、新 issue 维护者首评占比 0% 的 `strapi`。
- **能构建运行环境**。`validate` 阶段依赖 Docker（本机 26.1.3）；`healthchecks` 与 `halo` 直接有可用 Dockerfile。

## 目录与版本管理

```
targets/
├── README.md        # 本文件（入库）
├── registry.json    # 唯一事实源：pin、指标、源文件画像（入库）
├── healthchecks/    # 全历史 clone，detached 在 pinned_sha（不入库）
├── miniflux-v2/
└── halo/
```

- **全历史 clone**：init 阶段的 `security_history` 子图会审提交、构建补丁图，浅克隆会直接削弱该能力，所以不做 `--depth`。
- **固定版本**：每个目标 `git checkout --detach <pinned_sha>`；`fetch_targets.py` 会断言 `HEAD == pinned_sha`。上游漂移只能通过显式 `--refresh-pins` 更新。
- **不入库**：`.gitignore` 里 `targets/*` 忽略全部 clone，仅放行两个清单文件。分析产物默认写到 `targets/<id>/.yasa-vulnagent/runs/<run-id>/`，同样被忽略。

## 首次准备

```bash
bash scripts/bootstrap_env.sh                      # .venv (CPython 3.12) + 依赖 + YASA 二进制
python3 scripts/fetch_targets.py                   # 克隆并 pin 三个目标（全历史）
.venv/bin/python scripts/preflight_yasa.py         # G1：YASA 连通性预检
```

`bootstrap_env.sh` 做的事：用 `uv` 建 `.venv`（系统 `python3` 只有 3.8.10，项目要求 ≥3.10），`uv pip install -e .`，再把 YASA 原生二进制装到 `tools/yasa/linux-x86-64/{yasa,ripgrep,codegraph,scc}`。因为 `HOME` 只读，uv 的缓存与托管的 Python 都落在仓库内（`.uv-cache/`、`.uv-python/`，已 ignore）。

### YASA 原生二进制从哪来

`yasa_mcp` 的 init 同时需要 4 个原生工具，而 YASA-Engine 的 release 只发引擎，另外 3 个来自各自上游（都在 `tools/yasa-mcp/NOTICE.md` 里列了仓库）。`bootstrap_env.sh` 组装出的目录满足 `binary_layout.py` 的约定：

```text
tools/yasa/linux-x86-64/
├── yasa/yasa                  # antgroup/YASA-Engine  v0.3.3  (yasa-engine-linux-x64)
├── yasa/deps/uast4go          #                        (uast4go-linux-amd64)
├── yasa/deps/uast4py          #                        (uast4py-linux-amd64)
├── ripgrep/rg                 # BurntSushi/ripgrep     15.2.0
├── scc/scc                    # boyter/scc             v4.1.0
└── codegraph/bin/codegraph    # colbymchenry/codegraph  v1.6.2
```

版本可用环境变量覆盖：`ENGINE_VERSION` / `CODEGRAPH_VERSION` / `RIPGREP_VERSION` / `SCC_VERSION`。

### 沙箱带来的两个坑（已处理）

- **`$HOME` 只读**：`yasa_mcp` 启动时会 `mkdir ~/.yasamcp/logs`，直接 `OSError: Read-only file system`。脚本检测到 HOME 不可写时会改用仓库内 `.yasa-home/`（已 ignore）。
- **持久化 bin 路径先于 `--bin` 生效**：CLI 的 group callback 先调 `load_from_persisted()`，配置缺失时报 `Path .../linux-x86-64 does not exist`。脚本会把 `~/.yasamcp/config.json` 指向本仓库的 `tools/yasa`。

所以**直接跑 `yasa-vulnagent run`** 会遇到同样的两个错，请用下面的包装脚本。

## 预检（G1）在看什么

`scripts/preflight_yasa.py` 复刻 init 阶段 `yasa` 节点的逻辑（`src/yasa_vulnagent/stages/init/yasa/runner.py`）：

1. `yasa_mcp init <target> --bin tools/yasa` —— 生成结构化缓存（`<target>/.yasa/`）
2. `yasa_mcp status --project <target>` —— 断言 `valid: true`
3. MCP `get_function(name="main")` 探针 —— 只证明服务可达、返回合法 JSON，**空结果合法**

它刻意不跑 `documents` / `cwe` / `security_history`，也不创建 run record，所以迭代成本低。退出码非 0 表示有目标没通过。

本机实测（2026-11-02）：

| id | status_valid | MCP `get_function` 结果数 | 冷启动 init | 命中缓存后 |
|---|---|---|---|---|
| `healthchecks` | true | 0（合法，说明无 `main` 函数） | 32.1s | 3.3s |
| `miniflux-v2` | true | 1 | 18.4s | 2.5s |
| `halo` | true | 1 | 30.1s | 3.0s |

冷启动指清空 `<target>/.yasa/` 与 `<target>/.codegraph/` 后重新 init。缓存由 YASA 写在目标目录内，已被 `targets/*` 忽略。

## 后续分析

用包装脚本（自动处理 HOME 与 `~/.yasamcp/config.json`，参数原样透传）：

```bash
scripts/run_analysis.sh healthchecks
scripts/run_analysis.sh miniflux-v2 --audit-mode combined
scripts/run_analysis.sh halo --output-dir /data3/zhangyh/runs/halo

# 分阶段续跑
.venv/bin/yasa-vulnagent audit       --run-file <run.json>
.venv/bin/yasa-vulnagent environment --run-file <run.json>   # 构建 Docker 环境
.venv/bin/yasa-vulnagent validate    --run-file <run.json> --finding <id>
.venv/bin/yasa-vulnagent report      --run-file <run.json>
```

- `validate` 需要可达的 Docker daemon，缺失时该阶段 `blocked`，不会回退到宿主机执行。
- 建议顺序：`healthchecks`（26MB）→ `miniflux-v2`（39MB）→ `halo`（87MB，Java 文件最多，init 最慢）。
- 分阶段命令同样受 HOME 限制，手工跑时请先 `export HOME=$PWD/.yasa-home`。

## 刷新与新增

```bash
python3 scripts/fetch_targets.py --check                 # 只校验，不动工作区
python3 scripts/fetch_targets.py --only halo             # 只处理一个目标
python3 scripts/fetch_targets.py --refresh-pins          # 把 pin 跟到上游默认分支 HEAD，并刷新指标
```

新增第 4 个目标：在 `registry.json` 的 `targets` 里加一条（至少 `id` / `repo` / `url` / `default_branch` / `pinned_sha` / `local_dir`），再跑一次 `fetch_targets.py` 即可；`source_profile` 会被自动重算。

`--refresh-pins` 依赖 `gh`（已登录，5,000 次/小时）；取不到指标时保留旧值并告警，不中断。

## 已知限制

- YASA 只解析 `.java` `.py` `.js` `.ts` `.go` `.php`；`.tsx` `.jsx` `.vue` 不解析。`halo` 的前端是 Vue（392 个 `.vue`），因此它的分析实质集中在 Java 服务端。
- `miniflux-v2` 没有生产用根 `Dockerfile`，`validate` 阶段可能要让 environment 子图自建镜像。
- `healthchecks` 只有 1 条 2023 年的 advisory，`report` 阶段可锚定的历史较少。
- `miniflux-v2` 的维护者首评占比是三者中最低（15%），但仓库仍在每日推送；如更看重 issue 响应，可用 `--refresh-pins` 换目标前先评估。
- 指标是快照，不随上游自动更新；判断「是否仍活跃」请重跑 `--refresh-pins`。
