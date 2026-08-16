# Changelog

本项目的所有重要变更都记录在此文件。格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 新增

- GitHub Actions CI 上线（syntax + build + entry 验证 + auditDeep 自审冒烟），
  通过 esbuild 语法/打包校验 + peer stub 方案在公共环境跑通（完整 tsc 类型检查需 DSH 宿主提供 peer 类型）
- `.npmrc`（auto-install-peers=false）、`esbuild` devDependency、`check:syntax` 脚本

## [0.2.0] — 2026-08-16

### 新增

- **深度安全审查 `audit_deep`，三层能力**：
  - **Layer 1 — AST 语义分析**（acorn + acorn-walk）：解析包内全部 JS 系源码，
    检测 eval / `new Function`、child_process 动态执行、网络调用、
    敏感环境变量读取 + 网络外泄组合、fs 越权写（常量折叠真实路径判定）、
    vm 沙箱逃逸、`process.binding`/`dlopen` 原生注入、原型污染、
    混淆启发式（String.fromCharCode 链、base64+动态执行、高熵字符串、转义密度）、
    动态/远程 import；TS 源码降级为带置信度标注的浅扫
  - **Layer 2 — 依赖漏洞库**：20 条内置 CVE 快照（离线可用，按声明区间解析下限
    semver 比对）+ 在线 `npm audit`（无 lockfile 时在临时目录生成后扫描，
    registry/网络不可用自动降级为 info，不阻断）
  - **Layer 3 — 行为沙箱**：探针子进程 monkeypatch child_process / net / http(s) /
    fetch / WebSocket / fs 写删 / process.env，观测入口 import 期真实行为：
    子进程执行、写包外路径（如 Startup 目录）、网络信标、凭据读取与外传组合
- `audit_plugin` 与 `audit_gate` 支持 `deep=true` 参数；门禁要求浅层 PASS 且深层非 FAIL
- 修正 `readJsonFile` 对 UTF-8 BOM 的兼容

### 变更

- `ownPaths` 默认值改为空数组（原为作者本机路径），按部署环境在配置中设定
- package.json 描述修正为中文可读文本

### 开源

- MIT 许可、`.gitignore`、README 补全（环境要求/安装/构建/开发/已知边界）
- GitHub Actions CI：typecheck + build + 入口冒烟 + 深度自审

[0.2.0]: https://github.com/lht12345678/dsh-plugin-auditor/releases/tag/v0.2.0