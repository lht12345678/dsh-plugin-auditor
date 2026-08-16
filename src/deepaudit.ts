/**
 * dsh-plugin-auditor — 深度安全审查（Deep Security Review）。
 * 补足浅层审查（正则/文件扫描）的盲区，三层：
 *
 * 1. AST 语义分析（acorn + acorn-walk）
 *    解析包内全部 JS 系源码，检测危险调用模式（eval / child_process /
 *    网络 / fs 越权写 / 沙箱逃逸 / 原型污染 / 混淆启发式 / 敏感 env 读取），
 *    并带轻量数据流（require/import 绑定解析），比正则精确得多。
 *
 * 2. 依赖漏洞库
 *    内置精选已知漏洞快照（离线可用，semver 区间比对）+ 可选在线
 *    `npm audit --json`（有 lockfile 时执行，网络不可用优雅降级）。
 *
 * 3. 行为沙箱（探针子进程）
 *    子进程 --require 探针，monkeypatch child_process / net / http(s) /
 *    fetch / fs 写 / process.env，观察入口 import 期的真实行为并上报，
 *    补静态分析看不出的「运行时才动手」类恶意行为。
 *
 * 安全模型说明：沙箱是「检测」而非「遏制」——子进程与宿主同权限，
 * 探针只观察并透传调用；真正执行不受信任代码时应配合更低权限容器。
 */

import { parse } from 'acorn'
import * as walk from 'acorn-walk'
import { spawn } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir, homedir } from 'node:os'
import { basename, dirname, extname, join, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'
import { fingerprintDir, installedVersion, readJsonFile, resolveAny } from './util.js'
import { satisfies } from './semver.js'

// ── 类型 ────────────────────────────────────────────────────────────

export interface DeepFinding {
  id: string
  severity: 'fatal' | 'warn' | 'info'
  message: string
  layer: 'ast' | 'deps' | 'sandbox'
}

export interface DeepReport {
  verdict: 'PASS' | 'FAIL' | 'WARN'
  house: boolean
  name: string
  version: string
  entry: string
  fingerprint: string
  durationMs: number
  layers: {
    ast: { filesParsed: number; filesSkipped: string[]; findings: DeepFinding[] }
    deps: { mode: 'offline' | 'npm-audit' | 'unavailable'; findings: DeepFinding[] }
    sandbox: { loadOk: boolean; events: ProbeEvent[]; findings: DeepFinding[]; error?: string }
  }
  findings: DeepFinding[]
}

export interface DeepAuditOptions {
  dir: string
  house: boolean
  smokeTimeoutMs: number
}

// ── 内置漏洞快照（离线兜底；在线 npm audit 优先）─────────────────────────

interface VulnEntry {
  name: string
  range: string // semver 区间，如 "<4.17.21"
  cve: string
  severity: 'critical' | 'high' | 'moderate' | 'low'
  desc: string
}

const VULN_SNAPSHOT: VulnEntry[] = [
  { name: 'lodash', range: '<4.17.21', cve: 'CVE-2021-23337', severity: 'high', desc: '原型污染（constructor 链）' },
  { name: 'minimist', range: '<1.2.6', cve: 'CVE-2021-44906', severity: 'high', desc: '原型污染' },
  { name: 'node-fetch', range: '<2.6.7', cve: 'CVE-2022-0235', severity: 'high', desc: '重定向 SSRF / 凭据泄露' },
  { name: 'undici', range: '<5.26.2', cve: 'CVE-2023-45143', severity: 'high', desc: 'HTTP 头注入' },
  { name: 'tar', range: '<6.2.1', cve: 'CVE-2023-35165', severity: 'high', desc: '符号链接路径遍历（任意写）' },
  { name: 'minimatch', range: '<3.0.5', cve: 'CVE-2022-3517', severity: 'high', desc: 'ReDoS' },
  { name: 'semver', range: '<7.5.2', cve: 'CVE-2022-25883', severity: 'high', desc: 'ReDoS' },
  { name: 'jsonwebtoken', range: '<9.0.0', cve: 'CVE-2022-23529', severity: 'high', desc: '密钥混淆 RCE' },
  { name: 'ws', range: '<8.17.1', cve: 'CVE-2024-37890', severity: 'high', desc: 'DoS（帧处理）' },
  { name: 'axios', range: '<1.7.4', cve: 'CVE-2024-39338', severity: 'high', desc: '路径遍历（任意写）' },
  { name: 'follow-redirects', range: '<1.15.4', cve: 'CVE-2024-28849', severity: 'high', desc: '凭据泄露（重定向剥离认证头）' },
  { name: 'qs', range: '<6.10.3', cve: 'CVE-2022-24999', severity: 'high', desc: '原型污染' },
  { name: 'fast-xml-parser', range: '<4.4.1', cve: 'CVE-2024-41818', severity: 'moderate', desc: '原型污染' },
  { name: 'tough-cookie', range: '<4.1.3', cve: 'CVE-2023-26136', severity: 'moderate', desc: '原型污染' },
  { name: 'ip', range: '<2.0.1', cve: 'CVE-2023-42282', severity: 'high', desc: '任意文件读（IPv6 校验绕过）' },
  { name: 'braces', range: '<3.0.3', cve: 'CVE-2024-4068', severity: 'high', desc: 'ReDoS' },
  { name: 'ejs', range: '<3.1.7', cve: 'CVE-2022-29078', severity: 'critical', desc: '模板注入 RCE' },
  { name: 'nodemailer', range: '<6.6.1', cve: 'CVE-2021-3291', severity: 'high', desc: 'CRLF 注入' },
  { name: 'ssh2', range: '<1.15.0', cve: 'CVE-2023-48795', severity: 'high', desc: 'Terrapin 降级攻击' },
  { name: '@xmldom/xmldom', range: '<0.7.10', cve: 'CVE-2022-39353', severity: 'high', desc: 'XXE / 实体膨胀' },
]

const SENSITIVE_ENV_RE = /(^|_)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)(_|$)|^(AWS_|AZURE_|GCP_|OPENAI_|ANTHROPIC_|DEEPSEEK_)/i
const WRITE_FNS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'rm', 'rmSync', 'unlink', 'unlinkSync', 'rename', 'renameSync', 'copyFile', 'copyFileSync', 'createWriteStream', 'truncate', 'truncateSync', 'mkdtemp', 'mkdtempSync'])
const EXEC_FNS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'fork', 'execFile', 'execFileSync'])
const NET_MODS = new Set(['node:net', 'net', 'node:http', 'http', 'node:https', 'https', 'node:dns', 'dns', 'node:tls', 'tls', 'node:http2', 'http2'])
const VM_FNS = new Set(['runInNewContext', 'runInContext', 'runInThisContext', 'createContext'])
const DANGEROUS_FS_MODS = new Set(['node:fs', 'fs', 'node:fs/promises', 'fs/promises'])
const CHILD_PROC_MODS = new Set(['node:child_process', 'child_process'])
const JS_EXTS = new Set(['.js', '.mjs', '.cjs'])
const TS_EXTS = new Set(['.ts', '.mts', '.cts'])
const MAX_AST_FILE = 512 * 1024
const MAX_FILES = 3000

// ── AST 语义分析 ────────────────────────────────────────────────────

interface SourceFile {
  rel: string
  abs: string
  code: string
}

function collectSources(dir: string): { js: SourceFile[]; ts: SourceFile[]; skipped: string[] } {
  const js: SourceFile[] = []
  const ts: SourceFile[] = []
  const skipped: string[] = []
  let count = 0
  const walkDir = (d: string, prefix: string): void => {
    let entries: string[] = []
    try {
      entries = readdirSync(d)
    } catch {
      return
    }
    for (const e of entries) {
      if (count > MAX_FILES) return
      if (e === 'node_modules' || e === '.git' || e === 'dist' || e === 'coverage') continue
      const full = join(d, e)
      let st
      try {
        st = statSync(full)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        walkDir(full, prefix + e + '/')
        continue
      }
      count++
      const ext = extname(e).toLowerCase()
      if (!JS_EXTS.has(ext) && !TS_EXTS.has(ext)) continue
      if (st.size > MAX_AST_FILE) {
        skipped.push(prefix + e + `（${st.size}B > 512KB）`)
        continue
      }
      let code = ''
      try {
        code = readFileSync(full, 'utf8')
      } catch {
        skipped.push(prefix + e + '（不可读）')
        continue
      }
      const src = { rel: prefix + e, abs: full, code }
      if (JS_EXTS.has(ext)) js.push(src)
      else ts.push(src)
    }
  }
  walkDir(dir, '')
  return { js, ts, skipped }
}

/** 轻量数据流：模块顶层 require/import → 本地名 → 模块说明符。 */
function buildBindings(ast: any): Map<string, string> {
  const bind = new Map<string, string>()
  const add = (local: string, spec: string): void => {
    if (local && spec) bind.set(local, spec)
  }
  for (const node of ast.body ?? []) {
    if (node.type === 'ImportDeclaration' && typeof node.source?.value === 'string') {
      const spec = node.source.value
      for (const s of node.specifiers ?? []) {
        if (s.type === 'ImportDefaultSpecifier') add(s.local?.name, spec)
        else if (s.type === 'ImportNamespaceSpecifier') add(s.local?.name, spec)
        else if (s.type === 'ImportSpecifier') add(s.local?.name, spec)
      }
    } else if (node.type === 'VariableDeclaration') {
      for (const decl of node.declarations ?? []) {
        const init = decl.init
        if (!init || init.type !== 'CallExpression') continue
        const callee = init.callee
        if (callee?.type !== 'Identifier' || callee.name !== 'require') continue
        const arg = init.arguments?.[0]
        if (arg?.type !== 'Literal' || typeof arg.value !== 'string') continue
        const spec = arg.value
        if (decl.id?.type === 'Identifier') add(decl.id.name, spec)
        else if (decl.id?.type === 'ObjectPattern') {
          for (const p of decl.id.properties ?? []) {
            if (p.type === 'Property' && p.value?.type === 'Identifier') add(p.value.name, spec)
          }
        }
      }
    }
  }
  return bind
}

interface CalleeInfo {
  base: string
  module?: string
}

/** 解析调用点 callee → 基名 + 来源模块（含 process.env.X 链）。 */
function resolveCallee(node: any, bindings: Map<string, string>): CalleeInfo | null {
  if (!node) return null
  if (node.type === 'Identifier') {
    return { base: node.name, module: bindings.get(node.name) }
  }
  if (node.type === 'MemberExpression') {
    const obj = resolveCallee(node.object, bindings)
    if (!obj) return null
    let prop: string | null = null
    if (node.property?.type === 'Identifier') prop = node.property.name
    else if (node.property?.type === 'Literal' && typeof node.property.value === 'string') prop = node.property.value
    if (prop === null) return { base: obj.base + '.[dynamic]', module: obj.module }
    return { base: obj.base + '.' + prop, module: obj.module }
  }
  if (node.type === 'ThisExpression') return { base: 'this' }
  return null
}

function literalValue(node: any): string | null {
  if (!node) return null
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value
  if (node.type === 'TemplateLiteral' && (node.expressions?.length ?? 0) === 0) {
    return node.quasis?.map((q: any) => q.value?.cooked ?? '').join('') ?? null
  }
  return null
}

/** 常量折叠简单路径表达式：join/resolve(__dirname, 'lit')、字符串拼接。 */
function tryConstPath(node: any, baseDir: string): string | null {
  if (!node) return null
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return resolve(baseDir, node.value)
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const l = literalValue(node.left)
    const r = literalValue(node.right)
    if (l !== null && r !== null) return resolve(baseDir, l + r)
    return null
  }
  if (node.type === 'CallExpression') {
    const callee = resolveCallee(node.callee, new Map())
    const fn = callee?.base ?? ''
    const isJoin = fn === 'join' || fn.endsWith('.join')
    const isResolve = fn === 'resolve' || fn.endsWith('.resolve')
    if (isJoin || isResolve) {
      const parts: string[] = []
      for (const a of node.arguments ?? []) {
        if (a.type === 'Identifier' && (a.name === '__dirname' || a.name === '__filename')) {
          parts.push(a.name === '__dirname' ? baseDir : baseDir)
        } else if (a.type === 'Identifier' && a.name === 'process' && node.arguments.length === 0) {
          return null
        } else {
          const v = literalValue(a)
          if (v === null) return null
          parts.push(v)
        }
      }
      if (parts.length === 0) return null
      return resolve(parts[0], ...parts.slice(1))
    }
  }
  if (node.type === 'MemberExpression' && node.object?.type === 'Identifier') {
    const name = node.object.name
    if (name === '__dirname') return baseDir
    if (name === '__filename') return join(baseDir, 'index.js')
    if (name === 'process') {
      const prop = node.property?.name ?? node.property?.value
      if (prop === 'cwd' || prop === 'homedir') return null // 动态，视为不可判定
    }
  }
  if (node.type === 'Identifier' && node.name === 'process') return null
  return null
}

/** 路径是否落在包目录外（越权写判定）。 */
function isOutsidePkg(p: string, pkgRoot: string): boolean {
  const norm = (x: string): string => resolve(x).toLowerCase().replace(/\/$/, '')
  const root = norm(pkgRoot)
  const target = norm(p)
  if (target === root) return false
  if (target.startsWith(root + sep.toLowerCase())) return false
  const tmp = norm(tmpdir())
  if (target.startsWith(tmp + sep.toLowerCase()) || target === tmp) return false
  return true
}

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0
  const freq = new Map<string, number>()
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let h = 0
  for (const n of freq.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

const DANGEROUS_TS_PAT = [
  { id: 'ts-eval', re: /\beval\s*\(/, msg: 'eval 调用（TS 浅扫）' },
  { id: 'ts-exec', re: /(?<![\w$.])(?:exec|spawn|fork)(?:Sync)?\s*\(/, msg: '子进程调用（TS 浅扫）' },
  { id: 'ts-net', re: /(?<![\w$.])(?:fetch|https?\.(?:request|get)|net\.connect)\s*\(/, msg: '网络调用（TS 浅扫）' },
  { id: 'ts-fs-write', re: /(?<![\w$.])(?:writeFile|appendFile|createWriteStream|unlink|rm|rename|copyFile)(?:Sync)?\s*\(/, msg: '文件写/删操作（TS 浅扫）' },
  { id: 'ts-env', re: /process\.env\.[A-Za-z0-9_]+/, msg: 'process.env 读取（TS 浅扫）' },
  { id: 'ts-vm', re: /runIn(?:New)?Context\s*\(/, msg: 'vm 沙箱逃逸面（TS 浅扫）' },
  { id: 'ts-b64-eval', re: /(?:atob\s*\(|Buffer\.from\s*\([^)]*base64)[\s\S]{0,200}?(?:eval\s*\(|new\s+Function)/, msg: 'base64 解码 + 动态执行（TS 浅扫）' },
]

function scanTsLite(src: SourceFile, isExternal: boolean, findings: DeepFinding[]): void {
  for (const pat of DANGEROUS_TS_PAT) {
    if (pat.re.test(src.code)) {
      const sev = pat.id === 'ts-eval' || pat.id === 'ts-b64-eval' || pat.id === 'ts-vm' ? (isExternal ? 'fatal' : 'warn') : 'warn'
      findings.push({ id: pat.id, severity: sev, message: `${pat.msg}（${src.rel}，TS 未做 AST，浅扫置信度中）`, layer: 'ast' })
    }
  }
}

interface AstContext {
  findings: DeepFinding[]
  isExternal: boolean
  pkgRoot: string
  file: string
}

function analyzeAstFile(src: SourceFile, ctx: AstContext): { parsed: boolean; obf: { charcodes: number; b64exec: boolean; hiEntropy: number; escapes: number } } {
  const obf = { charcodes: 0, b64exec: false, hiEntropy: 0, escapes: 0 }
  let ast: any
  try {
    ast = parse(src.code, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      allowHashBang: true,
      allowReturnOutsideFunction: true,
      locations: true,
    })
  } catch {
    // ESM 解析失败（可能是 CJS 顶层 await 等极端场景）→ 退化为 script 再试
    try {
      ast = parse(src.code, { ecmaVersion: 'latest', sourceType: 'script', allowHashBang: true, allowReturnOutsideFunction: true, locations: true })
    } catch {
      return { parsed: false, obf }
    }
  }
  const bindings = buildBindings(ast)
  const line = (n: any): number => n?.loc?.start?.line ?? 0
  const sev = (warnMsg: string): 'fatal' | 'warn' => (ctx.isExternal ? 'fatal' : 'warn')
  const loc = (n: any): string => `${ctx.file}:${line(n)}`

  walk.full(ast, (node: any) => {
    // ── eval / Function 构造 ──
    if (node.type === 'CallExpression' && node.callee?.type === 'Identifier' && node.callee.name === 'eval') {
      ctx.findings.push({ id: 'ast-eval', severity: sev('eval'), message: `eval 调用（动态代码执行）@ ${loc(node)}`, layer: 'ast' })
    }
    if (node.type === 'NewExpression' && node.callee?.type === 'Identifier' && node.callee.name === 'Function') {
      ctx.findings.push({ id: 'ast-function-ctor', severity: sev('Function 构造'), message: `new Function 动态构造代码 @ ${loc(node)}`, layer: 'ast' })
    }

    // ── 动态 require / import ──
    if (node.type === 'CallExpression' && node.callee?.type === 'Identifier' && node.callee.name === 'require') {
      const arg = node.arguments?.[0]
      if (arg && literalValue(arg) === null) {
        ctx.findings.push({ id: 'ast-dynamic-require', severity: 'warn', message: `动态 require（非字面量参数）@ ${loc(node)}`, layer: 'ast' })
      }
    }
    if (node.type === 'ImportExpression') {
      const arg = node.source
      if (arg?.type === 'Literal' && typeof arg.value === 'string' && /^https?:|^data:|^file:\/\//.test(arg.value)) {
        ctx.findings.push({ id: 'ast-remote-import', severity: sev('远程 import'), message: `远程动态 import: ${arg.value.slice(0, 80)} @ ${loc(node)}`, layer: 'ast' })
      } else if (arg && literalValue(arg) === null) {
        ctx.findings.push({ id: 'ast-dynamic-import', severity: 'warn', message: `动态 import（非字面量参数）@ ${loc(node)}`, layer: 'ast' })
      }
    }

    // ── 各类成员调用 ──
    if (node.type === 'CallExpression' || node.type === 'NewExpression') {
      const info = resolveCallee(node.callee, bindings)
      if (!info) return
      const mod = info.module
      const base = info.base

      // child_process 执行
      if (mod && CHILD_PROC_MODS.has(mod)) {
        const fn = base.includes('.') ? base.slice(base.lastIndexOf('.') + 1) : base
        if (EXEC_FNS.has(fn)) {
          const cmd = literalValue(node.arguments?.[0])
          const dynamic = cmd === null
          ctx.findings.push({
            id: 'ast-process-exec',
            severity: sev('子进程执行'),
            message: `子进程执行 ${fn}(${cmd !== null ? JSON.stringify(cmd.slice(0, 80)) : '<动态命令>'})${dynamic ? '（命令为动态构造，无法判定内容）' : ''} @ ${loc(node)}`,
            layer: 'ast',
          })
        }
      }
      // 裸 spawn/exec（未绑定 require，直接全局引用 → 大概率动态）
      if (!mod && (base === 'exec' || base === 'execSync' || base === 'spawn' || base === 'fork')) {
        ctx.findings.push({ id: 'ast-process-exec-bare', severity: 'warn', message: `未绑定来源的子进程调用 ${base}(...) @ ${loc(node)}`, layer: 'ast' })
      }

      // 网络调用
      const isNetMod = mod !== undefined && NET_MODS.has(mod)
      if ((mod === undefined && (base === 'fetch' || base === 'WebSocket' || base === 'axios' || base === 'got')) || isNetMod) {
        const fn = base.includes('.') ? base.slice(base.lastIndexOf('.') + 1) : base
        const isNetFn = fn === 'request' || fn === 'get' || fn === 'connect' || fn === 'createConnection' || fn === 'lookup' || base === 'fetch' || base === 'WebSocket'
        if (isNetFn || (isNetMod && node.type === 'NewExpression')) {
          const target = literalValue(node.arguments?.[0])
          ctx.findings.push({
            id: 'ast-network',
            severity: 'warn',
            message: `网络调用 ${base}(${target !== null ? JSON.stringify(target.slice(0, 80)) : '<动态目标>'}) @ ${loc(node)}`,
            layer: 'ast',
          })
        }
      }

      // fs 写/删（越权判定）
      if (mod && DANGEROUS_FS_MODS.has(mod)) {
        const fn = base.includes('.') ? base.slice(base.lastIndexOf('.') + 1) : base
        if (WRITE_FNS.has(fn)) {
          const p = tryConstPath(node.arguments?.[0], ctx.pkgRoot)
          if (p !== null && isOutsidePkg(p, ctx.pkgRoot)) {
            ctx.findings.push({ id: 'ast-fs-write-outside', severity: sev('越权写文件'), message: `${fn} 写入包外路径: ${p} @ ${loc(node)}`, layer: 'ast' })
          } else if (p === null) {
            ctx.findings.push({ id: 'ast-fs-write-dynamic', severity: 'warn', message: `${fn}（目标路径动态构造，无法判定是否越权）@ ${loc(node)}`, layer: 'ast' })
          }
        }
      }

      // vm 沙箱逃逸面
      if (mod && VM_FNS.has(base.slice(base.lastIndexOf('.') + 1)) && (mod === 'node:vm' || mod === 'vm')) {
        ctx.findings.push({ id: 'ast-vm', severity: sev('vm 执行'), message: `vm.${base.slice(base.lastIndexOf('.') + 1)}(...) 动态执行 @ ${loc(node)}`, layer: 'ast' })
      }

      // String.fromCharCode 链（混淆）
      if (base === 'String.fromCharCode') {
        obf.charcodes += 1
      }

      // atob / Buffer base64（配合 eval 由文件级汇总判定）
      if (base === 'atob' || base === 'Buffer.from') {
        const args = node.arguments ?? []
        if (args.some((a: any) => literalValue(a)?.toLowerCase().includes('base64')) || base === 'atob') {
          // 在文件文本里看 200 字符窗口内是否紧跟 eval/new Function
          const idx = node.start ?? 0
          const window = src.code.slice(idx, idx + 300)
          if (/\beval\s*\(|new\s+Function/.test(window)) obf.b64exec = true
        }
      }
    }

    // ── 原型污染 ──
    if (node.type === 'AssignmentExpression' || node.type === 'UpdateExpression') {
      const target = node.type === 'AssignmentExpression' ? node.left : node.argument
      if (target?.type === 'MemberExpression') {
        const chain: string[] = []
        let cur = target
        while (cur?.type === 'MemberExpression') {
          const prop = cur.computed && cur.property?.type === 'Literal' ? String(cur.property.value) : cur.property?.name
          chain.unshift(prop ?? '?')
          cur = cur.object
        }
        if (chain.some((p) => p === '__proto__' || p === 'prototype')) {
          ctx.findings.push({ id: 'ast-proto-pollution', severity: 'warn', message: `原型链属性写入（${chain.join('.')}）@ ${loc(node)}`, layer: 'ast' })
        }
      }
    }

    // ── 敏感 env 读取 ──
    if (node.type === 'MemberExpression' && !node.computed) {
      const obj = resolveCallee(node.object, bindings)
      if (obj?.base === 'process.env' || obj?.base === 'process.env.[dynamic]') {
        const key = node.property?.name ?? ''
        if (SENSITIVE_ENV_RE.test(key)) {
          ctx.findings.push({ id: 'ast-env-sensitive', severity: 'warn', message: `读取敏感环境变量 process.env.${key} @ ${loc(node)}`, layer: 'ast' })
        }
      }
    }

    // ── 原生代码注入 ──
    if (node.type === 'CallExpression') {
      const base = resolveCallee(node.callee, bindings)?.base ?? ''
      if (base === 'process.binding' || base === 'process.dlopen') {
        ctx.findings.push({ id: 'ast-native-inject', severity: sev('原生代码注入'), message: `${base}(...) 加载原生模块 @ ${loc(node)}`, layer: 'ast' })
      }
    }
  })

  // ── 文件级混淆启发式 ──
  obf.escapes = (src.code.match(/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g) ?? []).length
  for (const m of src.code.matchAll(/"([^"\\\n]{24,})"/g)) {
    if (shannonEntropy(m[1]) > 4.2) obf.hiEntropy += 1
  }
  for (const m of src.code.matchAll(/'([^'\\\n]{24,})'/g)) {
    if (shannonEntropy(m[1]) > 4.2) obf.hiEntropy += 1
  }
  return { parsed: true, obf }
}

// ── 依赖漏洞库 ──────────────────────────────────────────────────────

/** 从区间提取基准版本（^1.2.3 / >=1.2.3 <2 → 1.2.3）；* / latest 视为未知。 */
function rangeFloor(range: string): string | null {
  if (/^(\*|latest|next)$/i.test(range.trim())) return null
  const m = /(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)/.exec(range)
  return m ? m[1] : null
}

function checkOfflineVulns(pkg: any, findings: DeepFinding[], isExternal: boolean): void {
  const deps: Record<string, string> = { ...(pkg.dependencies ?? {}) }
  for (const [name, range] of Object.entries<string>(deps)) {
    if (name.startsWith('link:') || name.startsWith('file:') || name.startsWith('workspace:')) continue
    const floor = rangeFloor(range)
    if (!floor) continue
    for (const vuln of VULN_SNAPSHOT) {
      if (name !== vuln.name && !name.endsWith('/' + vuln.name)) continue
      if (satisfies(floor, vuln.range) === true) {
        findings.push({
          id: 'dep-vuln-known',
          severity: isExternal ? 'fatal' : 'warn',
          message: `依赖 ${name}@${range} 的解析下限 ${floor} 落在已知漏洞 ${vuln.cve}（${vuln.severity}）: ${vuln.desc} —— 建议升到 ${vuln.range.replace(/[<>=~^ ]/g, '')} 以上`,
          layer: 'deps',
        })
      }
    }
  }
}

async function checkNpmAudit(dir: string, findings: DeepFinding[], isExternal: boolean): Promise<'offline' | 'npm-audit' | 'unavailable'> {
  // 有 lockfile 直接用；没有则在临时目录生成（只解析元数据，不装 node_modules）
  let auditDir = dir
  let tmp: string | null = null
  const hasLock = existsSync(join(dir, 'package-lock.json')) || existsSync(join(dir, 'npm-shrinkwrap.json'))
  if (!hasLock) {
    try {
      tmp = mkdtempSync(join(tmpdir(), 'dsh-auditor-npm-'))
      writeFileSync(join(tmp, 'package.json'), readFileSync(join(dir, 'package.json'), 'utf8'))
      const gen = await runNpm(['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], tmp, 60000)
      if (gen.code !== 0) {
        findings.push({ id: 'dep-audit-unavailable', severity: 'info', message: `在线 npm audit 不可用（生成 lockfile 失败 code=${gen.code}）: ${gen.err.slice(0, 120)}（已用内置快照兜底）`, layer: 'deps' })
        cleanupTmp(tmp)
        return 'unavailable'
      }
      auditDir = tmp
    } catch (e) {
      findings.push({ id: 'dep-audit-unavailable', severity: 'info', message: `在线 npm audit 不可用: ${String(e).slice(0, 120)}（已用内置快照兜底）`, layer: 'deps' })
      cleanupTmp(tmp)
      return 'unavailable'
    }
  }
  const r = await runNpm(['audit', '--json'], auditDir, 45000)
  cleanupTmp(tmp)
  const parsed = parseAuditJson(r.out)
  if (!parsed || r.code === null) {
    findings.push({ id: 'dep-audit-unavailable', severity: 'info', message: `在线 npm audit 无结果${r.code === null ? '（超时）' : `（code=${r.code}）`}: ${(r.err || r.out).slice(0, 160)}（已用内置快照兜底）`, layer: 'deps' })
    return 'unavailable'
  }
  for (const [name, v] of Object.entries<any>(parsed)) {
    const sev = v.severity ?? 'low'
    const viaTitle = Array.isArray(v.via)
      ? v.via.map((x: any) => (typeof x === 'string' ? x : x.title ?? x.url ?? '?')).slice(0, 3).join('; ')
      : String(v.via ?? '')
    const findingSev = sev === 'critical' || sev === 'high' ? (isExternal ? 'fatal' : 'warn') : sev === 'moderate' ? 'warn' : 'info'
    findings.push({
      id: 'dep-audit-vuln',
      severity: findingSev,
      message: `npm audit: ${name} ${sev}（direct=${v.isDirect ?? '?'}）: ${viaTitle || '未知漏洞'}`,
      layer: 'deps',
    })
  }
  return 'npm-audit'
}

function runNpm(args: string[], cwd: string, timeoutMs: number): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn('npm', args, { cwd, shell: true, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    child.stdout.on('data', (d) => (out += d))
    child.stderr.on('data', (d) => (err += d))
    const timer = setTimeout(() => {
      try {
        child.kill()
      } catch {
        /* 已退出 */
      }
    }, timeoutMs)
    child.on('error', (e) => {
      clearTimeout(timer)
      resolvePromise({ code: -1, out, err: String(e) })
    })
    child.on('exit', (code) => {
      clearTimeout(timer)
      resolvePromise({ code, out, err })
    })
  })
}

function cleanupTmp(tmp: string | null): void {
  if (!tmp) return
  try {
    rmSync(tmp, { recursive: true, force: true })
  } catch {
    /* 忽略 */
  }
}

function parseAuditJson(out: string): Record<string, any> | null {
  try {
    const j = JSON.parse(out)
    if (j && typeof j === 'object' && j.vulnerabilities) return j.vulnerabilities
    return null
  } catch {
    return null
  }
}

// ── 行为沙箱 ────────────────────────────────────────────────────────

const PROBE = [
  "// dsh-plugin-auditor sandbox probe (CJS) — 观察 import 期行为，透传调用",
  "const EMIT = (o) => { try { process.stderr.write('__DA__' + JSON.stringify(o) + '\\n') } catch {} }",
  "const SENSITIVE = /(^|_)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)(_|$)|^(AWS_|AZURE_|GCP_|OPENAI_|ANTHROPIC_|DEEPSEEK_)/i",
  "const hook = (modName, fnName, tag, map) => {",
  "  try {",
  "    const mod = require(modName)",
  "    const orig = mod[fnName]",
  "    if (typeof orig !== 'function') return",
  "    mod[fnName] = function () {",
  "      try { EMIT({ t: tag, d: map ? map(arguments) : '' }) } catch {}",
  "      return orig.apply(this, arguments)",
  "    }",
  "  } catch {}",
  "}",
  "['exec','execSync','spawn','spawnSync','fork','execFile','execFileSync'].forEach(fn => hook('node:child_process', fn, 'spawn', (a) => String(a[0]).slice(0, 200)));",
  "['request','get'].forEach(fn => { hook('node:http', fn, 'net', (a) => typeof a[0] === 'object' ? (a[0].hostname || a[0].host || '?') + ':' + (a[0].port || 80) : String(a[0]).slice(0, 200)) });",
  "['request','get'].forEach(fn => { hook('node:https', fn, 'net', (a) => typeof a[0] === 'object' ? (a[0].hostname || a[0].host || '?') + ':' + (a[0].port || 443) : String(a[0]).slice(0, 200)) });",
  "hook('node:net', 'connect', 'net', (a) => typeof a[0] === 'object' ? (a[0].host || '?') + ':' + (a[0].port || '?') : String(a[0]).slice(0, 200));",
  "hook('node:net', 'createConnection', 'net', (a) => typeof a[0] === 'object' ? (a[0].host || '?') + ':' + (a[0].port || '?') : String(a[0]).slice(0, 200));",
  "hook('node:dns', 'lookup', 'net', (a) => String(a[0]).slice(0, 200));",
  "['writeFile','writeFileSync','appendFile','appendFileSync','rm','rmSync','unlink','unlinkSync','rename','renameSync','copyFile','copyFileSync','createWriteStream','truncate','truncateSync'].forEach(fn => hook('node:fs', fn, 'fs-write', (a) => String(a[0]).slice(0, 240)));",
  "try { const g = globalThis; const of = g.fetch; if (of) g.fetch = function () { try { EMIT({ t: 'net', d: String(arguments[0]).slice(0, 200) }) } catch {}; return of.apply(this, arguments) } } catch {}",
  "try { const W = globalThis.WebSocket; if (W) globalThis.WebSocket = new Proxy(W, { construct(t, a) { try { EMIT({ t: 'net', d: String(a[0]).slice(0, 200) }) } catch {}; return new t(...a) } }) } catch {}",
  "try {",
  "  const real = process.env",
  "  const proxy = new Proxy(real, { get(t, k) { try { if (typeof k === 'string' && SENSITIVE.test(k)) EMIT({ t: 'env', d: k }) } catch {}; return t[k] } })",
  "  Object.defineProperty(process, 'env', { value: proxy, configurable: true, writable: true })",
  "} catch {}",
].join('\n')

interface ProbeEvent {
  t: string
  d: string
}

function runSandbox(
  entryFile: string,
  pkgRoot: string,
  timeoutMs: number,
): Promise<{ loadOk: boolean; events: ProbeEvent[]; error?: string }> {
  return new Promise((resolvePromise) => {
    let tmpDir: string | null = null
    try {
      tmpDir = mkdtempSync(join(tmpdir(), 'dsh-auditor-sandbox-'))
      const probePath = join(tmpDir, 'probe.cjs')
      writeFileSync(probePath, PROBE, 'utf8')
      const url = pathToFileURL(entryFile).href
      const code =
        `const u=process.argv[1];try{const m=await import(u);` +
        `const a=m.apply??m.default?.apply;if(typeof a!=='function'){` +
        `console.error('NO_APPLY:'+(m.name??'?'));process.exit(2)}` +
        `console.log('OK:'+(m.name??'?'))}catch(e){console.error('ERR:'+(e?.message??String(e)));process.exit(3)}`
      const child = spawn(
        process.execPath,
        ['--require', probePath, '--input-type=module', '-e', code, url],
        { cwd: pkgRoot, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
      )
      let err = ''
      let marker = ''
      child.stdout.on('data', () => undefined)
      child.stderr.on('data', (d) => {
        const s = String(d)
        for (const line of s.split('\n')) {
          if (line.startsWith('__DA__')) marker += line.slice(6) + '\n'
          else err += line + '\n'
        }
      })
      const timer = setTimeout(() => {
        try {
          child.kill()
        } catch {
          /* 已退出 */
        }
      }, timeoutMs)
      child.on('error', (e) => {
        clearTimeout(timer)
        cleanup()
        resolvePromise({ loadOk: false, events: parseEvents(marker), error: String(e).slice(0, 300) })
      })
      child.on('exit', (code) => {
        clearTimeout(timer)
        cleanup()
        const events = parseEvents(marker)
        if (code === 0) resolvePromise({ loadOk: true, events })
        else if (code === 2) resolvePromise({ loadOk: false, events, error: `入口未导出 apply()（${err.trim().slice(0, 200)}）` })
        else if (code === 3) resolvePromise({ loadOk: false, events, error: `加载异常: ${err.trim().slice(0, 500)}` })
        else if (code === null) resolvePromise({ loadOk: false, events, error: `加载超时（>${timeoutMs}ms）` })
        else resolvePromise({ loadOk: false, events, error: `加载失败 code=${code}: ${err.trim().slice(0, 300)}` })
      })
      const cleanup = (): void => {
        try {
          if (tmpDir) rmSync(tmpDir, { recursive: true, force: true })
        } catch {
          /* 忽略 */
        }
      }
    } catch (e) {
      try {
        if (tmpDir) rmSync(tmpDir, { recursive: true, force: true })
      } catch {
        /* 忽略 */
      }
      resolvePromise({ loadOk: false, events: [], error: `沙箱启动失败: ${String(e).slice(0, 300)}` })
    }
  })
}

function parseEvents(marker: string): ProbeEvent[] {
  const out: ProbeEvent[] = []
  const seen = new Set<string>()
  for (const line of marker.split('\n')) {
    if (!line.trim()) continue
    try {
      const j = JSON.parse(line)
      if (j && typeof j.t === 'string') {
        const key = j.t + '|' + String(j.d ?? '')
        if (seen.has(key)) continue
        seen.add(key)
        out.push({ t: j.t, d: String(j.d ?? '') })
      }
    } catch {
      /* 忽略坏行 */
    }
  }
  return out
}

// ── 入口 ────────────────────────────────────────────────────────────

export async function auditDeep(opts: DeepAuditOptions): Promise<DeepReport> {
  const t0 = Date.now()
  const dir = resolve(opts.dir)
  const pkg = readJsonFile(join(dir, 'package.json'))
  const name = String(pkg?.name ?? '?')
  const version = String(pkg?.version ?? '?')
  const isExternal = !opts.house

  const astFindings: DeepFinding[] = []
  const depsFindings: DeepFinding[] = []
  const sandboxFindings: DeepFinding[] = []

  // ── Layer 1: AST ──
  const { js, ts, skipped } = collectSources(dir)
  let filesParsed = 0
  for (const src of js) {
    const ctx: AstContext = { findings: astFindings, isExternal, pkgRoot: dir, file: src.rel }
    const r = analyzeAstFile(src, ctx)
    if (r.parsed) {
      filesParsed += 1
      if (r.obf.charcodes >= 3)
        astFindings.push({ id: 'ast-obf-charcodes', severity: 'warn', message: `混淆迹象: String.fromCharCode 链 ×${r.obf.charcodes}（${src.rel}）`, layer: 'ast' })
      if (r.obf.b64exec)
        astFindings.push({ id: 'ast-obf-b64-exec', severity: isExternal ? 'fatal' : 'warn', message: `混淆迹象: base64 解码紧跟 eval/new Function（${src.rel}）`, layer: 'ast' })
      if (r.obf.hiEntropy >= 8)
        astFindings.push({ id: 'ast-obf-entropy', severity: 'warn', message: `混淆迹象: 高熵字符串 ×${r.obf.hiEntropy}（${src.rel}）`, layer: 'ast' })
      if (r.obf.escapes >= 40)
        astFindings.push({ id: 'ast-obf-escapes', severity: 'warn', message: `混淆迹象: 十六进制/Unicode 转义密集 ×${r.obf.escapes}（${src.rel}）`, layer: 'ast' })
    }
  }
  for (const src of ts) scanTsLite(src, isExternal, astFindings)

  // 外泄组合：同包既有敏感 env 读取又有网络调用
  const hasEnv = astFindings.some((f) => f.id === 'ast-env-sensitive')
  const hasNet = astFindings.some((f) => f.id === 'ast-network')
  if (hasEnv && hasNet) {
    astFindings.push({
      id: 'ast-exfil-combo',
      severity: isExternal ? 'fatal' : 'warn',
      message: '外泄组合: 读取敏感环境变量 + 网络调用同存——疑似凭据外传',
      layer: 'ast',
    })
  }

  // ── Layer 2: 依赖漏洞 ──
  let depsMode: DeepReport['layers']['deps']['mode'] = 'offline'
  if (pkg) checkOfflineVulns(pkg, depsFindings, isExternal)
  depsMode = await checkNpmAudit(dir, depsFindings, isExternal)

  // ── Layer 3: 沙箱 ──
  let entryFile = join(dir, 'index.js')
  const entryRel = pkg?.main ?? pkg?.exports?.['.']?.import ?? pkg?.exports?.['.']?.default ?? 'index.js'
  const entryCandidate = join(dir, typeof entryRel === 'string' ? entryRel : 'index.js')
  if (existsSync(entryCandidate)) entryFile = entryCandidate
  const sandbox = await runSandbox(entryFile, dir, opts.smokeTimeoutMs)

  for (const ev of sandbox.events) {
    if (ev.t === 'spawn') {
      sandboxFindings.push({ id: 'sandbox-spawn', severity: isExternal ? 'fatal' : 'warn', message: `import 期执行子进程: ${ev.d}`, layer: 'sandbox' })
    } else if (ev.t === 'net') {
      sandboxFindings.push({ id: 'sandbox-net', severity: 'warn', message: `import 期发起网络连接: ${ev.d}`, layer: 'sandbox' })
    } else if (ev.t === 'fs-write') {
      const p = resolve(ev.d)
      if (isOutsidePkg(p, dir)) {
        sandboxFindings.push({ id: 'sandbox-fs-write-outside', severity: isExternal ? 'fatal' : 'warn', message: `import 期写包外路径: ${ev.d}`, layer: 'sandbox' })
      } else {
        sandboxFindings.push({ id: 'sandbox-fs-write', severity: 'info', message: `import 期写包内路径: ${ev.d}（放行）`, layer: 'sandbox' })
      }
    } else if (ev.t === 'env') {
      sandboxFindings.push({ id: 'sandbox-env', severity: 'warn', message: `import 期读取敏感环境变量: ${ev.d}`, layer: 'sandbox' })
    }
  }
  const sandboxNet = sandbox.events.some((e) => e.t === 'net')
  const sandboxEnv = sandbox.events.some((e) => e.t === 'env')
  if (sandboxNet && sandboxEnv) {
    sandboxFindings.push({ id: 'sandbox-exfil-combo', severity: isExternal ? 'fatal' : 'warn', message: '沙箱观测到 网络连接 + 敏感环境变量读取 组合——疑似凭据外传', layer: 'sandbox' })
  }

  const findings = [...astFindings, ...depsFindings, ...sandboxFindings]
  const hasFatal = findings.some((f) => f.severity === 'fatal')
  const hasWarn = findings.some((f) => f.severity === 'warn')
  const verdict: DeepReport['verdict'] = hasFatal ? 'FAIL' : hasWarn ? 'WARN' : 'PASS'

  return {
    verdict,
    house: opts.house,
    name,
    version,
    entry: entryRel,
    fingerprint: fingerprintDir(dir),
    durationMs: Date.now() - t0,
    layers: {
      ast: { filesParsed, filesSkipped: skipped.slice(0, 20), findings: astFindings },
      deps: { mode: depsMode, findings: depsFindings },
      sandbox: { loadOk: sandbox.loadOk, events: sandbox.events.slice(0, 60), findings: sandboxFindings, error: sandbox.error },
    },
    findings,
  }
}
