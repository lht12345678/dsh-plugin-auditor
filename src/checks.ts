/**
 * dsh-plugin-auditor — 审计引擎：对单个插件包做静态审查 + 冒烟加载。
 * 分四组：结构 / 依赖兼容 / 装配冲突（防崩溃核心）/ 安全扫描，另有自研 house rules。
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { basename, dirname, extname, join, resolve } from 'node:path'
import { parseVersion, satisfies } from './semver.js'
import { parsePatch } from './yaml.js'
import {
  fingerprintDir,
  hostNodeModules,
  installedVersion,
  nodeCheck,
  profileDir,
  resolveAny,
  resolveFrom,
  smokeImport,
} from './util.js'

export interface Finding {
  id: string
  severity: 'fatal' | 'warn' | 'info'
  message: string
}

export interface AuditReport {
  verdict: 'PASS' | 'FAIL'
  house: boolean
  name: string
  version: string
  entry: string
  fingerprint: string
  durationMs: number
  findings: Finding[]
}

export interface AuditOptions {
  dir: string
  house: boolean
  smokeTimeoutMs: number
  installedBundleNames: string[]
  patchIds: string[]
  loaderNames: string[]
  /** profile cordis.patch.yml 全文（用于同 id 内容比对，区分同源合并与真覆盖冲突）。 */
  profilePatchText?: string
}

const SECRET_RE =
  /(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer [A-Za-z0-9._-]{20,})/g
const DANGER_RE = /(rm\s+-rf|Remove-Item\s+-Recurse|del\s+\/s|>nul|format\s+[a-zA-Z]:|shutdown\s+\/s)/i
const TEXT_EXTS = new Set(['.ts', '.js', '.mjs', '.cjs', '.json', '.yml', '.yaml', '.md', '.txt', '.sh', '.ps1', '.toml', '.ini'])
const BINARY_EXTS = new Set(['.exe', '.dll', '.scr', '.bat', '.cmd', '.jar'])

interface ScanResult {
  secrets: string[]
  binaries: string[]
  envFiles: string[]
}

function scanFiles(dir: string): ScanResult {
  const out: ScanResult = { secrets: [], binaries: [], envFiles: [] }
  let count = 0
  const walk = (d: string): void => {
    if (count > 3000) return
    let entries: string[] = []
    try {
      entries = readdirSync(d)
    } catch {
      return
    }
    for (const e of entries) {
      if (count > 3000) return
      if (e === 'node_modules' || e === '.git') continue
      const full = join(d, e)
      let st
      try {
        st = statSync(full)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        walk(full)
        continue
      }
      count++
      const rel = full.slice(dir.length + 1)
      const ext = extname(e).toLowerCase()
      if (BINARY_EXTS.has(ext) && st.size < 64 * 1024 * 1024) {
        out.binaries.push(rel)
        continue
      }
      if (/^\.env|credential|secret|\.pem$/i.test(e)) {
        out.envFiles.push(rel)
      }
      if (TEXT_EXTS.has(ext) && st.size < 256 * 1024) {
        try {
          const text = readFileSync(full, 'utf8')
          for (const m of text.matchAll(SECRET_RE)) {
            out.secrets.push(`${rel}: ${String(m[0]).slice(0, 24)}…`)
            if (out.secrets.length >= 3) return
          }
        } catch {
          /* 跳过 */
        }
      }
    }
  }
  walk(dir)
  return out
}

/** 判定是否为「自研」：路径位于 ownPaths，或包名符合本地命名约定。 */
export function isOwnPath(dir: string, name: string, ownPaths: string[]): boolean {
  const p = dir.toLowerCase().replace(/\\/g, '/')
  if (ownPaths.some((o) => p.startsWith(o.toLowerCase().replace(/\\/g, '/')))) return true
  return /^(dsh-|@dsh-external\/|@omdsh-dev\/)/.test(name || '')
}

/** 把 patch 文本按 `- id:` 切成 id → 原文块 的映射（用于同源比对）。 */
export function splitPatchBlocks(text: string): Map<string, string> {
  const m = new Map<string, string>()
  const lines = text.split(/\r?\n/)
  let cur: string | null = null
  let block: string[] = []
  for (const line of lines) {
    const hit = /^\s*-\s*id:\s*(\S+)\s*$/.exec(line)
    if (hit) {
      if (cur) m.set(cur, block.join('\n'))
      cur = hit[1]
      block = [line]
    } else if (cur) block.push(line)
  }
  if (cur) m.set(cur, block.join('\n'))
  return m
}

export async function auditCandidate(opts: AuditOptions): Promise<AuditReport> {
  const t0 = Date.now()
  const findings: Finding[] = []
  const f = (id: string, severity: Finding['severity'], message: string): void => {
    findings.push({ id, severity, message })
  }
  const dir = resolve(opts.dir)
  const profileNm = join(profileDir(), 'node_modules')
  const hostNm = hostNodeModules()

  // ── 结构 ──────────────────────────────────────────────
  const pkgPath = join(dir, 'package.json')
  let pkg: any
  try {
    pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))
  } catch {
    f('pkg-missing', 'fatal', `package.json 缺失或不可解析（${pkgPath}）`)
    return report()
  }
  const name = String(pkg.name ?? '')
  const version = String(pkg.version ?? '')
  if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(name))
    f('name-invalid', 'fatal', `包名无效: ${JSON.stringify(name)}`)
  if (!parseVersion(version)) f('version-invalid', 'fatal', `版本号无效: ${JSON.stringify(version)}`)

  let entryRel = pkg.main
  if (!entryRel && pkg.exports) {
    const dot = pkg.exports['.'] ?? pkg.exports
    if (typeof dot === 'string') entryRel = dot
    else entryRel = dot?.import ?? dot?.default
  }
  if (!entryRel) f('no-entry', 'fatal', '未声明 main/exports（DSH 无法定位入口）')
  const entryPath = entryRel ? join(dir, entryRel) : join(dir, 'index.js')
  if (!existsSync(entryPath)) f('entry-missing', 'fatal', `入口文件不存在: ${entryRel ?? '(默认 index.js)'}`)
  const ext = extname(entryPath).toLowerCase()
  if (existsSync(entryPath) && ['.js', '.mjs', '.cjs'].includes(ext)) {
    const chk = nodeCheck(entryPath, opts.smokeTimeoutMs)
    if (chk) f('entry-syntax', 'fatal', `入口语法检查失败: ${chk}`)
    else {
      const sm = await smokeImport(entryPath, opts.smokeTimeoutMs)
      if (!sm.ok) f('entry-load', 'fatal', `入口冒烟加载失败: ${sm.error}`)
    }
  } else if (existsSync(entryPath)) {
    f('entry-type', 'fatal', `入口是 ${ext} 文件（${entryRel}）——DSH 只加载 .js/.mjs/.cjs，需要先构建`)
  }

  // ── 依赖兼容 ──────────────────────────────────────────
  for (const dep of Object.keys(pkg.dependencies ?? {})) {
    if (resolveFrom(dir, dep) || resolveAny(dep)) continue
    f('dep-missing', 'fatal', `依赖缺失: ${dep}（候选目录 / profile node_modules / host node_modules 均解析不到）`)
  }
  for (const [dep, range] of Object.entries<string>(pkg.peerDependencies ?? {})) {
    const inst = resolveAny(dep)
    if (!inst) {
      f('peer-missing', 'fatal', `peerDependency 未安装: ${dep}@${range}`)
      continue
    }
    const ver = installedVersion(inst)
    if (!ver) {
      f('peer-unreadable', 'warn', `无法读取已装版本: ${dep}（${inst}）`)
      continue
    }
    const ok = satisfies(ver, range)
    if (ok === false) f('peer-conflict', 'fatal', `peerDependency 冲突: ${dep} 要求 ${range}，实际已装 ${ver}`)
    else if (ok === null) f('peer-range-unparseable', 'warn', `无法解析版本区间（跳过）: ${dep}@${range}`)
  }

  // ── 装配冲突（防崩溃核心）─────────────────────────────
  // 已装配的包（体检模式）：重复项是身份确认，降级 info；未装配的包（安装前审查）：重复即崩溃源。
  const installed = opts.installedBundleNames.includes(name) && name !== ''
  if (installed) {
    f('bundle-dup', 'info', `已装配在 profile bundles（体检模式，非重复装配）`)
  } else if (name) {
    f('bundle-dup', 'fatal', `bundle 重复: ${name} 已在 profile bundles 中——重复加载会导致 duplicate loader entry id 崩溃`)
  }
  if (opts.loaderNames.includes(name) && name) {
    f(
      'loader-dup',
      installed ? 'info' : 'fatal',
      installed ? `已加载（体检模式）` : `同名插件已加载: ${name}（loader 树中已存在）`,
    )
  }
  const patchPath = join(dir, 'cordis.patch.yml')
  if (existsSync(patchPath)) {
    const ownText = readFileSync(patchPath, 'utf8')
    const own = parsePatch(ownText)
    const profileBlocks = splitPatchBlocks(opts.profilePatchText ?? '')
    const seen = new Set<string>()
    for (const e of own) {
      if (seen.has(e.id)) f('patch-dup-internal', 'fatal', `自身 patch 内重复 id: ${e.id}`)
      seen.add(e.id)
      if (opts.patchIds.includes(e.id)) {
        const ownBlock = (splitPatchBlocks(ownText).get(e.id) ?? '').replace(/\s+/g, ' ').trim()
        const profileBlock = (profileBlocks.get(e.id) ?? '').replace(/\s+/g, ' ').trim()
        if (ownBlock && ownBlock === profileBlock)
          f(
            'patch-same-source',
            'warn',
            `patch id 与 profile 补丁同源（已合并过）: ${e.id}——重装时可能重复合并，产生重复 patch id 崩溃风险`,
          )
        else f('patch-conflict', 'fatal', `patch id 冲突: ${e.id} 已存在于 profile 补丁且内容不同——可能静默覆盖`)
      }
    }
  }

  // ── 自研 house rules（额外收严）───────────────────────
  if (opts.house) {
    if (!existsSync(join(dir, 'lib'))) f('house-no-lib', 'fatal', '自研插件未构建：缺 lib/（先跑 npm run build）')
    if (pkg.private !== true) f('house-not-private', 'warn', '自研本地插件建议 private: true，避免误发注册表')
    if (!pkg.scripts?.build) f('house-no-build', 'warn', '建议声明 scripts.build（build.sh 构建链）')
  } else if (existsSync(join(dir, 'src')) && !existsSync(join(dir, 'lib'))) {
    f('src-only', 'warn', '只有 src/ 没有 lib/——确认交付的是构建后产物')
  }

  // ── 安全扫描 ──────────────────────────────────────────
  const isExternal = !opts.house
  const scripts = pkg.scripts ?? {}
  for (const k of ['preinstall', 'install', 'postinstall'] as const) {
    if (scripts[k])
      f('install-script', isExternal ? 'fatal' : 'warn', `安装脚本 ${k}: ${String(scripts[k]).slice(0, 90)}（外部插件供应链风险）`)
  }
  if (DANGER_RE.test(Object.values(scripts).join('\n')))
    f('danger-script', 'warn', 'scripts 含危险命令模式（rm -rf / del /s 等）')
  const scan = scanFiles(dir)
  for (const s of scan.secrets) f('secret', isExternal ? 'fatal' : 'warn', `发现疑似密钥: ${s}`)
  for (const b of scan.binaries) f('binary', isExternal ? 'fatal' : 'warn', `包内二进制文件: ${b}`)
  for (const e of scan.envFiles) f('env-file', isExternal ? 'fatal' : 'warn', `包内环境/凭据文件: ${e}`)
  if (!pkg.license) f('no-license', 'warn', '未声明 license')

  const fingerprint = fingerprintDir(dir)

  function report(): AuditReport {
    const hasFatal = findings.some((x) => x.severity === 'fatal')
    return {
      verdict: hasFatal ? 'FAIL' : 'PASS',
      house: opts.house,
      name,
      version,
      entry: entryRel ?? '',
      fingerprint,
      durationMs: Date.now() - t0,
      findings,
    }
  }
  return report()
}
