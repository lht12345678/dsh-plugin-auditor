# @dsh-external/dsh-plugin-auditor — 插件审计官

[![CI](https://github.com/lht12345678/dsh-plugin-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/lht12345678/dsh-plugin-auditor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/github/v/release/lht12345678/dsh-plugin-auditor)](https://github.com/lht12345678/dsh-plugin-auditor/releases)

> 为 [DeepSeek Harness (DSH)](https://github.com/deepseek-ai/deepseek-harness) 打造的插件
> 「审计官 + 门卫 + 保险丝」三合一。任何插件（外来或自研）**必须先过它这关才能安装**：

- **审查**：静态审查 + 冒烟加载，出裁决书（PASS/FAIL + 逐项 findings）
- **深度安全审查**：`audit_deep`（三层：AST 语义分析 + 依赖漏洞库 + 行为沙箱），可接入门禁
- **门禁**：只有拿到台账回执的插件才被放行；未过审插件硬阻断（fiber 停用 + 写禁用补丁）
- **兼容扫描**：全量扫描 bundles / patch / loader 树冲突（专治 duplicate loader entry id、重复 patch id 崩溃）
- **保险丝**：插件崩溃（fiber FAILED）自动记录 + 写禁用补丁（带备份），防 harness 反复崩溃

## 环境要求

- Node.js ≥ 20（沙箱探针依赖 `--require` 预载与 ESM 加载）
- DeepSeek Harness 运行时（提供 `cordis` / `@deepseek-ai/dsh-tools` / `@deepseek-ai/dsh-llm` 等 peer 依赖）
- TypeScript ≥ 5.x 与 bash（仅构建时需要）

## 安装

```bash
# 在 DSH profile 内
git clone https://github.com/lht12345678/dsh-plugin-auditor
cd dsh-plugin-auditor && bash scripts/build.sh
# 然后通过 DSH 的 dev_install_package / dsh plugin add 装配
```

> 审计官是「先装后审」闭环：装好后首次启动会基准豁免存量插件，
> 之后所有新插件必须 `audit_gate` 过审才有台账回执，否则被守卫拦截。

## 工具

| 工具 | 作用 |
|---|---|
| `audit_plugin <path> [deep]` | 审查单个插件包（静态+冒烟），出裁决书（不写台账）；`deep=true` 附加深度安全审查 |
| `audit_gate <path> [note] [deep]` | **门禁入口**：审查通过才写台账回执；`deep=true` 时深度审查 FAIL 同样拒绝 |
| `audit_deep <path>` | **深度安全审查**：AST 语义 + 依赖漏洞库 + 行为沙箱，出三层独立裁决 |
| `audit_all` | 全量兼容扫描：bundles/patch/loader 冲突、缺依赖、未过审名单 |
| `audit_ledger [name]` | 查台账：过审/豁免/被拒/崩溃记录 |
| `audit_guard [key value]` | 守卫状态/策略运行时调整（`requireReceipt` block\|warn、`autoDisable` true\|false） |
| `audit_recover <list\|enable\|disable> [entryId]` | 崩溃恢复：列记录 / 回滚禁用 / 手动禁用 |

## 使用流程

```
1. audit_gate <插件目录>          # 审查 → PASS 则写入台账回执
2. dev_install_package <目录>     # 或 dsh plugin add —— 守卫放行
```

- 自研插件（`dsh-*` / `@dsh-external/*` / `@omdsh-dev/*` 或位于配置的 `ownPaths`）自动走 **house rules**（要求 `lib/` 构建产物、`private: true` 等额外检查）
- `@deepseek-ai/*` 官方核心插件自动豁免
- 审计官首装时的存量插件一次性**祖父豁免**（grandfathered），之后新装的都必须过审

## 策略（配置 / 运行时）

| 配置 | 默认 | 说明 |
|---|---|---|
| `requireReceipt` | `block` | `block`=未过审硬阻断；`warn`=仅告警 |
| `autoDisable` | `true` | 崩溃后自动写禁用补丁 |
| `corePrefixes` | `@deepseek-ai/`, `cordis:`, `node:` | 豁免前缀 |
| `ownPaths` | `[]` | 自研目录（触发 house rules）；按你的环境配置，如 `['/Users/you/plugins']` |
| `smokeTimeoutMs` | 20000 | 冒烟加载超时 |

运行时调整：`audit_guard requireReceipt warn` / `audit_guard autoDisable false`（写入 `~/.dsh/plugin-auditor/state.json` overrides）。

## 审查项（fatal = 裁决 FAIL）

- **结构**：package.json 合法性、入口存在且为 .js/.mjs/.cjs、`node --check` 语法、子进程冒烟 import（验证导出 apply()）
- **依赖**：dependencies 可解析（候选目录/profile/host node_modules）、peerDependencies 与已装版本 semver 冲突
- **装配冲突（防崩溃核心）**：bundle 名重复、loader 同名已加载、patch id 与 profile 补丁冲突、自身 patch 重复 id
- **安全（外部插件从严）**：安装脚本（postinstall 供应链风险）、密钥模式扫描（sk-/ghp_/AKIA/私钥）、.env/凭据文件、危险脚本命令、包内二进制
- **house rules（自研）**：必须已构建（lib/ 存在）、建议 private: true、建议声明 scripts.build

## 深度安全审查（audit_deep，三层）

浅层审查（正则/文件级）挡不住「明晃晃的雷」之外的恶意插件，`audit_deep` 补三层：

### 1. AST 语义分析（acorn + acorn-walk）
对包内全部 JS 系源码（lib/src/client，跳过 node_modules/.git/dist）做真实语法树分析，
比正则精确得多，可识别：

- `eval` / `new Function` 动态代码执行（外部 fatal）
- `child_process` 的 exec/spawn/fork（动态构造命令 fatal，字面量命令 warn）
- 网络调用 fetch / http(s).request / net.connect / WebSocket（warn，配合敏感 env 读取升 fatal）
- **外泄组合**：同包读取敏感环境变量（`*KEY*`/`*TOKEN*`/`*SECRET*`/AWS_/OPENAI_…）+ 网络调用 → fatal
- fs 写入包目录之外（常量折叠 path.join/resolve/`__dirname` 后判定真实路径）
- `vm.runInNewContext` 沙箱逃逸面、`process.binding`/`dlopen` 原生注入
- `__proto__` / `prototype` 原型污染写入
- 混淆启发式：String.fromCharCode 链、base64 解码紧跟 eval/new Function（fatal）、
  高熵字符串、十六进制转义密度
- 动态 require/import（非字面量）、远程 import（http/data/file 协议）
- TS 源码降级为正则浅扫（标注「TS 未做 AST」）

### 2. 依赖漏洞库
- **内置离线快照**：20 条精选已知漏洞（lodash/minimist/node-fetch/undici/tar/axios/semver/ws/ejs…），
  按「声明区间解析下限」semver 比对（`^4.17.20` → 下限 4.17.20 → 命中 `<4.17.21` 即报）
- **在线 npm audit**：有 lockfile 直接用；无 lockfile 时在临时目录生成后扫描；
  网络/registry 不可用自动降级 info，不阻断

### 3. 行为沙箱（探针子进程）
子进程 `--require` 探针，monkeypatch `child_process`/`net`/`http(s)`/`fetch`/`WebSocket`/
`fs` 写删/`process.env`，观察**入口 import 期真实行为**并上报：

- import 期执行子进程（外部 fatal）
- import 期写包外路径（如 Startup 目录/主目录——fatal）
- import 期发起网络连接、读取敏感环境变量（warn）
- 网络 + 敏感 env 组合 → 疑似凭据外传（fatal）

> ⚠️ 沙箱是「检测」而非「遏制」：子进程与宿主同权限，探针只观察并透传调用；
> 真正执行不受信任代码时应配合更低权限容器。沙箱只覆盖 import 顶层副作用，
> 函数体内的行为靠 AST 静态补齐。

### 裁决合并
`verdict = FAIL if 任一 fatal / WARN if 任一 warn / PASS`。外部插件从严（多数 fatal），
house 自研插件宽松一档（多数 warn）。`audit_gate --deep` 要求**浅层 PASS 且深层非 FAIL** 才放行。

## 数据

- 台账：`~/.dsh/plugin-auditor/ledger.jsonl`（receipt / grandfathered / blocked / failure 全记录）
- 状态：`~/.dsh/plugin-auditor/state.json`（启动快照、崩溃记录、策略 overrides）
- 禁用补丁：写 `profiles/<profile>/cordis.patch.yml`，每次修改前自动备份 `cordis.patch.yml.audit-bak-<ts>`

## 构建

```bash
# 依赖 dev 工具链（tsc/@types/node 从 DSH 运行时或 DSH_CHECKOUT 解析）
bash scripts/build.sh   # 链接类型依赖 + tsc 编译 src → lib

# 或单独类型检查
npm run typecheck
```

## 开发

- `src/` 为 TypeScript 源码，`lib/` 为构建产物（git 忽略，不提交）
- 新增审查项：在 `src/checks.ts`（浅层）或 `src/deepaudit.ts`（深度三层）中加规则，样式与既有 `Finding { id, severity, message }` 一致
- 新增工具：在 `src/index.ts` 用 `ctx.tools.register(defineTool({...}))` 注册，输出经 `toJson` 归一化
- 行为沙箱探针是运行时生成的 `.cjs` 模板（`src/deepaudit.ts` 内 `PROBE` 常量），修改后无需额外构建步骤

## 已知边界

- 守卫监听 `internal/plugin`（fiber 创建）与 `internal/status`（FAILED）；启动完成判定用「entries 计数稳定探测」（本 cordis 无 ready 事件）
- 冒烟加载在子进程执行，顶层副作用不波及 harness 本身
- `dsh plugin add` CLI 直装未过审插件时，守卫会在**下次启动**的基线比对中拦截并禁用
- 深度沙箱是「检测」而非「遏制」（详见上文）

## 变更记录

版本历史见 [CHANGELOG.md](CHANGELOG.md)。

## 许可

MIT。见 [LICENSE](LICENSE)。
