/**
 * dsh-plugin-auditor — 台账（ledger.jsonl）+ 引导状态（state.json）。
 * 台账是「进过审计官的手」的唯一凭证：receipt（正式回执）/ grandfathered（旧装豁免）/
 * self（审计官自己）/ blocked（门禁拒绝）/ failure（崩溃记录）。
 */
import { appendFileSync, existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { AUDITOR_VERSION, auditorHome, ensureDir, readJsonFile, writeJsonFile } from './util.js'

export type LedgerKind = 'receipt' | 'grandfathered' | 'self' | 'blocked' | 'unvetted' | 'failure'

export interface LedgerEntry {
  ts: string
  kind: LedgerKind
  name: string
  version?: string
  entryId?: string
  fingerprint?: string
  house?: boolean
  verdict?: string
  note?: string
  auditor: string
}

const ledgerFile = (): string => join(auditorHome(), 'ledger.jsonl')

export function appendLedger(e: Omit<LedgerEntry, 'ts' | 'auditor'>): void {
  ensureDir(auditorHome())
  appendFileSync(ledgerFile(), JSON.stringify({ ...e, ts: new Date().toISOString(), auditor: AUDITOR_VERSION }) + '\n', 'utf8')
}

export function queryLedger(name?: string, kind?: LedgerKind): LedgerEntry[] {
  if (!existsSync(ledgerFile())) return []
  const out: LedgerEntry[] = []
  for (const line of readFileSync(ledgerFile(), 'utf8').split('\n')) {
    if (!line.trim()) continue
    try {
      const e = JSON.parse(line) as LedgerEntry
      if (name !== undefined && e.name !== name) continue
      if (kind !== undefined && e.kind !== kind) continue
      out.push(e)
    } catch {
      /* 坏行跳过 */
    }
  }
  return out.reverse()
}

/** 是否具备放行凭证（任一类型即可；重建后同名仍放行，内容变更由审计环节负责）。 */
export function hasReceipt(name: string): boolean {
  return queryLedger(name).some((e) => e.kind === 'receipt' || e.kind === 'self' || e.kind === 'grandfathered')
}

export interface SnapshotEntry {
  id: string
  name: string
}

export interface BootState {
  baselineDone: boolean
  snapshot: SnapshotEntry[]
  failures: { entryId: string; name: string; ts: string; reason: string }[]
  overrides: { requireReceipt?: 'block' | 'warn'; autoDisable?: boolean }
}

const stateFile = (): string => join(auditorHome(), 'state.json')

export function readState(): BootState {
  const s = readJsonFile(stateFile())
  return {
    baselineDone: s?.baselineDone === true,
    snapshot: Array.isArray(s?.snapshot) ? s.snapshot : [],
    failures: Array.isArray(s?.failures) ? s.failures : [],
    overrides: s?.overrides ?? {},
  }
}

export function writeState(s: BootState): void {
  writeJsonFile(stateFile(), s)
}
