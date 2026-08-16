/**
 * dsh-plugin-auditor — 运行时守卫：门禁（未过审插件硬阻断）+ 保险丝（fiber 崩溃自动禁用）。
 * 事件面：internal/plugin（fiber 创建）/ internal/status（状态迁移）在 ctx.root 监听全量。
 * 基线时机：本 cordis 无 ready 事件，用「entries 计数稳定探测」判定启动完成。
 */
import type { Context } from 'cordis'
import '@deepseek-ai/cordis-plugin-loader'
import { join } from 'node:path'
import { appendLedger, hasReceipt, readState, writeState } from './ledger.js'
import { isCore, profileDir } from './util.js'
import { writePatchDisabled } from './yaml.js'

export interface GuardConfig {
  requireReceipt: 'block' | 'warn'
  autoDisable: boolean
  corePrefixes: string[]
}

const FIBER_STATE_FAILED = 3
const STABLE_ROUNDS = 2
const POLL_MS = 1200
const MAX_POLLS = 12

export function startGuard(ctx: Context, config: GuardConfig): () => void {
  const disposers: Array<() => void> = []
  const state = readState()
  const gated = new Set<string>()
  const handled = new Set<string>()
  const pending: string[] = []
  let ready = false
  let baselineScheduled = false
  let timer: NodeJS.Timeout | undefined
  const patchPath = join(profileDir(), 'cordis.patch.yml')

  const effPolicy = (): { requireReceipt: 'block' | 'warn'; autoDisable: boolean } => ({
    requireReceipt: state.overrides.requireReceipt ?? config.requireReceipt,
    autoDisable: state.overrides.autoDisable ?? config.autoDisable,
  })

  function findEntry(id: string | undefined) {
    if (!id) return undefined
    for (const e of ctx.loader.entries()) if (e.id === id) return e
    return undefined
  }

  /** 未过审新插件 → 按策略门禁。 */
  function gateNew(entryId: string, fiber?: any): void {
    if (gated.has(entryId)) return
    gated.add(entryId)
    const entry = findEntry(entryId)
    const name = entry?.options.name ?? entryId
    if (!name) return
    if (isCore(name, config.corePrefixes)) return
    if (name.startsWith('@dsh-external/dsh-plugin-auditor') || name === '@dsh-external/dsh-super-injector') return
    if (hasReceipt(name)) return
    const policy = effPolicy()
    if (policy.requireReceipt === 'block') {
      appendLedger({ kind: 'blocked', name, entryId, note: '门禁硬阻断' })
      // 用事件携带的 fiber 直接停（internal/plugin 触发时 entry.fiber 可能尚未赋值）
      try {
        const target = fiber ?? entry?.fiber
        if (target?.dispose) void target.dispose()
      } catch {
        /* 停用尽力而为 */
      }
      try {
        const r = writePatchDisabled(patchPath, entryId, true)
        ctx.logger.warn(
          `[dsh-plugin-auditor] 门禁拦截 ${name}（${entryId}）：台账无凭证，fiber 已停用` +
            (r.changed ? `，禁用补丁已写入（备份 ${r.backup}）` : ''),
        )
      } catch (e) {
        ctx.logger.error(`[dsh-plugin-auditor] 写禁用补丁失败: ${String(e).slice(0, 300)}`)
      }
    } else {
      appendLedger({ kind: 'unvetted', name, entryId, note: '策略=warn 仅告警' })
      ctx.logger.warn(`[dsh-plugin-auditor] 未过审插件加载（策略=warn）: ${name}（${entryId}）`)
    }
  }

  // 启动完成：首次运行祖父豁免；此后与上次快照比对，boot 新增未过审插件照拦
  function finalizeBaseline(): void {
    ready = true
    const entries = [...ctx.loader.entries()].map((e) => ({ id: e.id, name: e.options.name }))
    if (!state.baselineDone) {
      for (const e of entries) {
        if (!e.name || isCore(e.name, config.corePrefixes)) continue
        if (e.name.startsWith('@dsh-external/dsh-plugin-auditor')) continue
        if (!hasReceipt(e.name))
          appendLedger({ kind: 'grandfathered', name: e.name, entryId: e.id, note: '审计官首装基线豁免' })
      }
      state.baselineDone = true
      ctx.logger.info(`[dsh-plugin-auditor] 首装基线完成：豁免 ${entries.length} 个 loader entry`)
    } else {
      const prev = new Map(state.snapshot.map((s) => [s.id, s.name]))
      for (const e of entries) {
        if (prev.get(e.id) === e.name) continue
        if (!e.name || isCore(e.name, config.corePrefixes)) continue
        if (e.name.startsWith('@dsh-external/dsh-plugin-auditor')) continue
        gateNew(e.id)
      }
    }
    state.snapshot = entries
    writeState(state)
    // 等待期间到达的新 fiber 补走门禁
    for (const id of pending) gateNew(id)
    pending.length = 0
  }

  function scheduleBaseline(): void {
    if (baselineScheduled) return
    baselineScheduled = true
    let stable = 0
    let lastCount = -1
    let polls = 0
    const tick = (): void => {
      const count = [...ctx.loader.entries()].length
      if (count === lastCount) {
        stable += 1
        if (stable >= STABLE_ROUNDS) {
          finalizeBaseline()
          return
        }
      } else {
        stable = 0
        lastCount = count
      }
      polls += 1
      if (polls >= MAX_POLLS) {
        finalizeBaseline()
        return
      }
      timer = setTimeout(tick, POLL_MS)
    }
    timer = setTimeout(tick, POLL_MS)
  }

  // fiber 创建：运行时注入（dev_install_package / dev_inject_plugin）的新插件在此出现
  disposers.push(
    ctx.root.on('internal/plugin', (fiber: any) => {
      if (!fiber) return
      const id = ctx.loader.locate(fiber) ?? fiber.entry?.id
      if (!id) return
      if (ready) gateNew(id, fiber)
      else pending.push(id)
    }),
  )

  // 状态迁移：fiber FAILED = 插件崩溃 → 记录 + 自动禁用（从 apply 起即生效）
  disposers.push(
    ctx.root.on('internal/status', (fiber: any, oldState: number) => {
      if (!fiber || fiber.state !== FIBER_STATE_FAILED) return
      const id = ctx.loader.locate(fiber) ?? fiber.entry?.id ?? '?'
      if (handled.has(id)) return
      const entry = findEntry(id)
      const name = entry?.options.name ?? id
      state.failures.push({ entryId: id, name, ts: new Date().toISOString(), reason: 'fiber FAILED' })
      writeState(state)
      appendLedger({ kind: 'failure', name, entryId: id, note: 'fiber FAILED' })
      const policy = effPolicy()
      if (policy.autoDisable && id !== '?') {
        handled.add(id)
        try {
          const r = writePatchDisabled(patchPath, id, true)
          ctx.logger.error(
            `[dsh-plugin-auditor] 插件崩溃已自动禁用 ${name}（${id}）` +
              (r.changed ? `，补丁备份 ${r.backup}` : '（补丁已存在）'),
          )
        } catch (e) {
          ctx.logger.error(`[dsh-plugin-auditor] 崩溃后写补丁失败: ${String(e).slice(0, 300)}`)
        }
      } else {
        ctx.logger.error(`[dsh-plugin-auditor] 插件崩溃（autoDisable=off）: ${name}（${id}）`)
      }
    }),
  )

  scheduleBaseline()

  return () => {
    if (timer) clearTimeout(timer)
    for (const d of disposers) {
      try {
        d()
      } catch {
        /* 忽略 */
      }
    }
  }
}
