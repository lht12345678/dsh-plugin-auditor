/**
 * dsh-plugin-auditor — 全量兼容扫描：profile bundles / patch / loader 树 / 依赖互查。
 * 专治两类崩溃：duplicate loader entry id、重复 patch id。
 */
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { parsePatch } from './yaml.js'
import { satisfies } from './semver.js'
import { readJsonFile, resolveFrom, installedVersion } from './util.js'
import type { Finding } from './checks.js'

export interface LoaderEntryView {
  id: string
  name: string
  disabled: boolean
  state: string
}

export interface CompatReport {
  verdict: 'PASS' | 'FAIL' | 'WARN'
  findings: Finding[]
  summary: {
    bundles: number
    patchEntries: number
    loaderEntries: number
    unvetted: string[]
  }
}

export function scanCompat(opts: {
  profileDir: string
  loaderEntries: LoaderEntryView[]
  ledgerNames: string[]
  corePrefixes: string[]
}): CompatReport {
  const findings: Finding[] = []
  const f = (id: string, severity: Finding['severity'], message: string): void => {
    findings.push({ id, severity, message })
  }
  const { profileDir: pdir, loaderEntries } = opts
  const profileNm = join(pdir, 'node_modules')
  const profilePkg = readJsonFile(join(pdir, 'package.json'))
  const bundles: string[] = Array.isArray(profilePkg?.dsh?.profile?.bundles) ? profilePkg.dsh.profile.bundles : []

  // ── bundles ───────────────────────────────────────────
  const seenBundles = new Map<string, number>()
  for (const b of bundles) seenBundles.set(b, (seenBundles.get(b) ?? 0) + 1)
  for (const [b, n] of seenBundles) {
    if (n > 1) f('bundle-dup', 'fatal', `profile bundles 内重复: ${b} ×${n}（duplicate loader entry id 崩溃源）`)
    else if (!resolveFrom(profileNm, b) && !resolveFrom(join(profileNm, '@deepseek-ai'), b) && !resolveFrom(join(profileNm, '..', '..', '..', '..', 'resources', 'host', 'node_modules'), b))
      f('bundle-unresolvable', 'fatal', `bundle 解析不到: ${b}（profile node_modules 中不存在）`)
  }

  // ── patch ─────────────────────────────────────────────
  const patchPath = join(pdir, 'cordis.patch.yml')
  const patchEntries = parsePatch(existsSync(patchPath) ? readFileSync(patchPath, 'utf8') : '')
  const seenPatch = new Map<string, number>()
  for (const e of patchEntries) seenPatch.set(e.id, (seenPatch.get(e.id) ?? 0) + 1)
  // include 的 patch id 是组内短名（如 attachment-local 对应 loader 树里的 include:attachment-local），按末段匹配
  const loaderIds = new Set(loaderEntries.map((e) => e.id))
  const loaderLeafIds = new Set(loaderEntries.map((e) => e.id.split(':').pop()))
  for (const [id, n] of seenPatch) {
    if (n > 1) f('patch-dup', 'fatal', `profile 补丁内重复 id: ${id} ×${n}（启动崩溃源，可用 fix-patch 清理）`)
    // disabled 条目是「防未安装插件被装配」的合法语义，即使目标不存在也不算 stale
    const e = patchEntries.find((x) => x.id === id)
    if (!e?.disabled && !bundles.includes(id) && !loaderIds.has(id) && !loaderLeafIds.has(id) && !id.startsWith('dsh-auditor'))
      f('patch-stale', 'warn', `补丁目标不存在: ${id}（未匹配任何 bundle/entry，可能是残留）`)
  }

  // ── loader 树 ─────────────────────────────────────────
  const seenIds = new Map<string, number>()
  let disabledCount = 0
  const bySubtree = new Map<string, Map<string, number>>() // 子树 → name → active 计数
  for (const e of loaderEntries) {
    seenIds.set(e.id, (seenIds.get(e.id) ?? 0) + 1)
    if (e.state === 'failed') f('fiber-failed', 'fatal', `插件已崩溃: ${e.id}（fiber FAILED）`)
    else if (e.disabled) disabledCount += 1
    if (!e.name || e.name === 'cordis:group') continue
    if (e.disabled) continue // disabled 条目不算双加载
    const parent = e.id.includes(':') ? e.id.slice(0, e.id.lastIndexOf(':')) : '(root)'
    let m = bySubtree.get(parent)
    if (!m) {
      m = new Map()
      bySubtree.set(parent, m)
    }
    m.set(e.name, (m.get(e.name) ?? 0) + 1)
  }
  for (const [id, n] of seenIds) if (n > 1) f('entry-dup-id', 'fatal', `loader 树重复 entry id: ${id} ×${n}`)
  // 同子树内同名且都 active：多为多 entry 复用同一模块（如 tool-subagent/tool-subagent-fork），
  // cordis 模块缓存下不崩；真正的崩溃源（同 id 重复装配）已由 entry-dup-id 守住，故降级为 warn。
  for (const [parent, m] of bySubtree) {
    for (const [name, n] of m) {
      if (n > 1)
        f('entry-dup-name', 'warn', `同子树模块复用: ${name} ×${n}（父=${parent}；确认是有意复用，若为重复装配则需处理）`)
    }
  }
  if (disabledCount > 0) f('fiber-disabled', 'info', `已禁用条目合计: ${disabledCount} 个（host 默认或补丁禁用）`)

  // ── 已装插件互查 peer ─────────────────────────────────
  const scanned = new Set<string>()
  const scanPeer = (pkgDir: string, display: string): void => {
    if (scanned.has(pkgDir)) return
    scanned.add(pkgDir)
    const pkg = readJsonFile(join(pkgDir, 'package.json'))
    if (!pkg?.peerDependencies) return
    for (const [dep, range] of Object.entries<string>(pkg.peerDependencies)) {
      const inst = resolveFrom(profileNm, dep) ?? resolveFrom(join(pkgDir, '..'), dep)
      if (!inst) {
        f('peer-missing', 'warn', `${display} 的 peer 未装: ${dep}@${range}`)
        continue
      }
      const ver = installedVersion(inst)
      if (ver && satisfies(ver, range) === false)
        f('peer-conflict', 'warn', `peer 冲突: ${display} 要求 ${dep}@${range}，实际 ${ver}`)
    }
  }
  for (const b of bundles) {
    const resolved = resolveFrom(profileNm, b)
    if (resolved) scanPeer(resolved, b)
  }

  // ── 未过审名单（跳过相对路径条目与审计官自身）──────────
  const unvetted = loaderEntries
    .filter(
      (e) =>
        e.name &&
        !e.disabled &&
        !opts.ledgerNames.includes(e.name) &&
        !opts.corePrefixes.some((p) => e.name.startsWith(p)) &&
        !e.name.startsWith('./') &&
        !e.name.startsWith('../') &&
        !e.name.startsWith('@dsh-external/dsh-plugin-auditor'),
    )
    .map((e) => e.name)
  for (const n of unvetted) f('unvetted', 'warn', `未过审插件: ${n}（台账无凭证）`)

  const hasFatal = findings.some((x) => x.severity === 'fatal')
  return {
    verdict: hasFatal ? 'FAIL' : findings.some((x) => x.severity === 'warn') ? 'WARN' : 'PASS',
    findings,
    summary: {
      bundles: bundles.length,
      patchEntries: patchEntries.length,
      loaderEntries: loaderEntries.length,
      unvetted,
    },
  }
}
