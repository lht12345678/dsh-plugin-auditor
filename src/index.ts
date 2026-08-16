/**
 * dsh-plugin-auditor — 插件审计官：审查 / 门禁 / 兼容扫描 / 崩溃保险丝。
 * 铁律：任何插件（外来或自研）必须先过 audit_gate 拿到台账回执，守卫才会放行；
 * fiber 崩溃自动写禁用补丁（带备份），防 harness 反复崩溃。
 */
import type { Context } from 'cordis'
import '@deepseek-ai/cordis-plugin-loader'
import z from 'schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-session'
import { existsSync, readFileSync } from 'node:fs'
import { auditCandidate, isOwnPath } from './checks.js'
import { auditDeep, type DeepReport } from './deepaudit.js'
import { scanCompat, type LoaderEntryView } from './compat.js'
import { startGuard } from './guard.js'
import { appendLedger, queryLedger, readState, writeState } from './ledger.js'
import { auditorHome, profileDir, readJsonFile } from './util.js'
import { parsePatch, writePatchDisabled } from './yaml.js'

export const name = 'dsh-plugin-auditor'
export const inject = ['tools', 'loader']

export interface Config {
  requireReceipt: 'block' | 'warn'
  autoDisable: boolean
  corePrefixes: string[]
  ownPaths: string[]
  smokeTimeoutMs: number
}

export const Config = z.object({
  requireReceipt: z.union([z.const('block'), z.const('warn')]).default('block'),
  autoDisable: z.boolean().default(true),
  corePrefixes: z.array(z.string()).default(['@deepseek-ai/', 'cordis:', 'node:']),
  ownPaths: z.array(z.string()).default([]),
  smokeTimeoutMs: z.number().default(20000),
})

const STATE_LABEL: Record<number, string> = { 0: 'pending', 1: 'loading', 2: 'active', 3: 'failed', 4: 'disposed', 5: 'unloading' }

function loaderViews(ctx: Context): LoaderEntryView[] {
  return [...ctx.loader.entries()].map((e) => ({
    id: e.id,
    name: e.options.name,
    disabled: e.disabled,
    state: STATE_LABEL[e.fiber?.state as number] ?? '?',
  }))
}

function renderJson(_args: unknown, value: unknown) {
  return [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }]
}

/** 工具返回统一 JSON 归一化（接口类型无索引签名，转纯 JSON 才满足输出 schema）。 */
const toJson = <T,>(v: T): Record<string, JsonValue> => JSON.parse(JSON.stringify(v)) as Record<string, JsonValue>

export function apply(ctx: Context, config: Config): void {
  ctx.effect(() => startGuard(ctx, config), 'dsh-plugin-auditor: guard')

  ctx.effect(
    () =>
      ctx.tools.register(
        defineTool({
          name: 'audit_plugin',
          description: '审查单个插件包（静态+冒烟），出裁决书，不写台账；deep=true 时附加深度安全审查（AST+漏洞库+沙箱）',
          parameters: {
            path: { type: 'string', required: true, description: '插件包目录' },
            house: { type: 'boolean', description: '强制按自研标准审' },
            deep: { type: 'boolean', description: '附加深度安全审查（三层：AST 语义/依赖漏洞/行为沙箱）' },
          },
          output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
          async execute(args: { path: string; house?: boolean; deep?: boolean }) {
            const pkg = readJsonFile(`${args.path}/package.json`)
            const house = args.house ?? isOwnPath(args.path, pkg?.name, config.ownPaths)
            const report = await auditCandidate({
              dir: args.path,
              house,
              smokeTimeoutMs: config.smokeTimeoutMs,
              installedBundleNames: bundlesOf(profileDir()),
              patchIds: patchIdsOf(profileDir()),
              profilePatchText: profilePatchText(),
              loaderNames: [...ctx.loader.entries()].map((e) => e.options.name),
            })
            if (!args.deep) return toJson(report)
            const deep = await auditDeep({ dir: args.path, house, smokeTimeoutMs: config.smokeTimeoutMs })
            return toJson({ ...report, deep })
          },
        }),
      ),
    'dsh-plugin-auditor: audit_plugin',
  )

  ctx.effect(
    () =>
      ctx.tools.register(
        defineTool({
          name: 'audit_deep',
          description: '深度安全审查：AST 语义分析（eval/子进程/网络/越权写/沙箱逃逸/混淆）+ 依赖漏洞库（内置快照+可选 npm audit）+ 行为沙箱（import 期行为观测）',
          parameters: {
            path: { type: 'string', required: true, description: '插件包目录' },
            house: { type: 'boolean', description: '强制按自研标准审（宽松一档）' },
          },
          output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
          async execute(args: { path: string; house?: boolean }) {
            const pkg = readJsonFile(`${args.path}/package.json`)
            const house = args.house ?? isOwnPath(args.path, pkg?.name, config.ownPaths)
            return toJson(await auditDeep({ dir: args.path, house, smokeTimeoutMs: config.smokeTimeoutMs }))
          },
        }),
      ),
    'dsh-plugin-auditor: audit_deep',
  )

  ctx.effect(
    () =>
      ctx.tools.register(
        defineTool({
          name: 'audit_gate',
          description: '门禁入口：审查通过才写台账回执，插件才算过审（未过审会被守卫拦截）；deep=true 时深度审查 FAIL 同样拒绝',
          parameters: {
            path: { type: 'string', required: true, description: '插件包目录' },
            note: { type: 'string', description: '备注（来源/用途）' },
            deep: { type: 'boolean', description: '同时跑深度安全审查（AST+漏洞库+沙箱），FAIL 拒绝放行' },
          },
          output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
          async execute(args: { path: string; note?: string; deep?: boolean }) {
            const pkg = readJsonFile(`${args.path}/package.json`)
            const house = isOwnPath(args.path, pkg?.name, config.ownPaths)
            const report = await auditCandidate({
              dir: args.path,
              house,
              smokeTimeoutMs: config.smokeTimeoutMs,
              installedBundleNames: bundlesOf(profileDir()),
              patchIds: patchIdsOf(profileDir()),
              profilePatchText: profilePatchText(),
              loaderNames: [...ctx.loader.entries()].map((e) => e.options.name),
            })
            const deep: DeepReport | undefined = args.deep
              ? await auditDeep({ dir: args.path, house, smokeTimeoutMs: config.smokeTimeoutMs })
              : undefined
            if (report.verdict !== 'PASS' || (deep && deep.verdict === 'FAIL')) {
              return toJson({ gate: 'DENIED', message: '未通过审计，不写入账回执', report, deep })
            }
            appendLedger({
              kind: 'receipt',
              name: report.name,
              version: report.version,
              fingerprint: report.fingerprint,
              house: report.house,
              verdict: 'PASS',
              note: args.note ?? '',
            })
            return toJson({
              gate: 'PASS',
              message: '已写入台账回执，可安装',
              receipt: { name: report.name, version: report.version, fingerprint: report.fingerprint },
              report,
              deep,
            })
          },
        }),
      ),
    'dsh-plugin-auditor: audit_gate',
  )

  ctx.effect(
    () =>
      ctx.tools.register(
        defineTool({
          name: 'audit_all',
          description: '全量兼容扫描：bundles/patch/loader 冲突、缺依赖、未过审名单',
          parameters: {},
          output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
          async execute() {
            const ledgerNames = [...new Set(queryLedger().map((e) => e.name))]
            return toJson(
              scanCompat({
                profileDir: profileDir(),
                loaderEntries: loaderViews(ctx),
                ledgerNames,
                corePrefixes: config.corePrefixes,
              }),
            )
          },
        }),
      ),
    'dsh-plugin-auditor: audit_all',
  )

  ctx.effect(
    () =>
      ctx.tools.register(
        defineTool({
          name: 'audit_ledger',
          description: '查台账：插件是否过审/豁免/被拒/崩溃记录',
          parameters: {
            name: { type: 'string', description: '按包名过滤' },
          },
          output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
          async execute(args: { name?: string }) {
            const entries = queryLedger(args.name).slice(0, 60)
            return toJson({ count: entries.length, entries })
          },
        }),
      ),
    'dsh-plugin-auditor: audit_ledger',
  )

  ctx.effect(
    () =>
      ctx.tools.register(
        defineTool({
          name: 'audit_guard',
          description: '守卫状态/策略：requireReceipt(block|warn)、autoDisable(true|false) 运行时可调',
          parameters: {
            key: { type: 'string', description: 'requireReceipt | autoDisable' },
            value: { type: 'string', description: 'block/warn 或 true/false' },
          },
          output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
          async execute(args: { key?: string; value?: string }) {
            const state = readState()
            if (args.key) {
              if (args.key === 'requireReceipt' && (args.value === 'block' || args.value === 'warn')) {
                state.overrides.requireReceipt = args.value
                writeState(state)
              } else if (args.key === 'autoDisable' && (args.value === 'true' || args.value === 'false')) {
                state.overrides.autoDisable = args.value === 'true'
                writeState(state)
              } else {
                return toJson({ error: `无效参数: ${args.key}=${args.value}` })
              }
            }
            const s = readState()
            return toJson({
              policy: {
                requireReceipt: s.overrides.requireReceipt ?? config.requireReceipt,
                autoDisable: s.overrides.autoDisable ?? config.autoDisable,
                corePrefixes: config.corePrefixes,
              },
              baselineDone: s.baselineDone,
              snapshotCount: s.snapshot.length,
              failures: s.failures.slice(-10),
              home: auditorHome(),
            })
          },
        }),
      ),
    'dsh-plugin-auditor: audit_guard',
  )

  ctx.effect(
    () =>
      ctx.tools.register(
        defineTool({
          name: 'audit_recover',
          description: '崩溃恢复：列崩溃记录；enable/disable 插件（写禁用补丁，带备份）',
          parameters: {
            action: { type: 'string', required: true, description: 'list | enable | disable' },
            entryId: { type: 'string', description: 'enable/disable 的 entry id' },
          },
          output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
          async execute(args: { action: string; entryId?: string }) {
            const state = readState()
            const patchPath = `${profileDir()}/cordis.patch.yml`
            if (args.action === 'list') {
              const ledgerFailures = queryLedger(undefined, 'failure').slice(0, 20)
              return toJson({ bootFailures: state.failures.slice(-20), ledgerFailures })
            }
            if (!args.entryId) return toJson({ error: '需要 entryId' })
            if (args.action === 'disable') {
              const r = writePatchDisabled(patchPath, args.entryId, true)
              return toJson({ action: 'disabled', entryId: args.entryId, result: r })
            }
            if (args.action === 'enable') {
              const r = writePatchDisabled(patchPath, args.entryId, false)
              state.failures = state.failures.filter((x) => x.entryId !== args.entryId)
              writeState(state)
              return toJson({ action: 'enabled', entryId: args.entryId, result: r })
            }
            return toJson({ error: `未知动作: ${args.action}` })
          },
        }),
      ),
    'dsh-plugin-auditor: audit_recover',
  )
}

function bundlesOf(pdir: string): string[] {
  const pkg = readJsonFile(`${pdir}/package.json`)
  return Array.isArray(pkg?.dsh?.profile?.bundles) ? pkg.dsh.profile.bundles : []
}

function patchIdsOf(pdir: string): string[] {
  const p = `${pdir}/cordis.patch.yml`
  if (!existsSync(p)) return []
  return parsePatch(readFileSync(p, 'utf8')).map((e) => e.id)
}

function profilePatchText(): string | undefined {
  const p = `${profileDir()}/cordis.patch.yml`
  return existsSync(p) ? readFileSync(p, 'utf8') : undefined
}
