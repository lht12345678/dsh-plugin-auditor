/**
 * dsh-plugin-auditor — cordis.patch.yml 最小方言解析/外科手术编辑。
 * 只关心 `- id: X` 与同级 `disabled:` 字段，其余行原样保留。
 */
import { copyFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

export interface PatchEntry {
  id: string
  disabled: boolean
  idLine: number
  disabledLine?: number
}

export function parsePatch(text: string): PatchEntry[] {
  const lines = text.split(/\r?\n/)
  const entries: PatchEntry[] = []
  let cur: PatchEntry | null = null
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const m = /^\s*-\s*id:\s*(\S+)\s*$/.exec(line)
    if (m) {
      cur = { id: m[1], disabled: false, idLine: i }
      entries.push(cur)
      continue
    }
    const d = /^\s*disabled:\s*(true|false)\s*$/.exec(line)
    if (d && cur && cur.disabledLine === undefined) {
      cur.disabled = d[1] === 'true'
      cur.disabledLine = i
    }
  }
  return entries
}

export interface PatchChange {
  text: string
  action: 'added' | 'updated' | 'removed' | 'noop'
}

export function applyPatchChange(text: string, id: string, disabled: boolean): PatchChange {
  const entries = parsePatch(text)
  const e = entries.find((x) => x.id === id)
  if (!e) {
    if (!disabled) return { text, action: 'noop' }
    const t = text.endsWith('\n') ? text : text + '\n'
    return { text: t + `- id: ${id}\n  disabled: true\n`, action: 'added' }
  }
  const lines = text.split(/\r?\n/)
  if (disabled) {
    if (e.disabledLine !== undefined) {
      if (/disabled:\s*true/.test(lines[e.disabledLine])) return { text, action: 'noop' }
      lines[e.disabledLine] = lines[e.disabledLine].replace(/disabled:\s*false/, 'disabled: true')
      return { text: lines.join('\n'), action: 'updated' }
    }
    lines.splice(e.idLine + 1, 0, '  disabled: true')
    return { text: lines.join('\n'), action: 'added' }
  }
  if (e.disabledLine !== undefined) {
    lines.splice(e.disabledLine, 1)
    return { text: lines.join('\n'), action: 'removed' }
  }
  return { text, action: 'noop' }
}

export interface PatchWriteResult {
  action: PatchChange['action']
  backup?: string
  changed: boolean
}

/** 写 profile 禁用补丁：先备份（.audit-bak-<ts>），再外科手术改一行。 */
export function writePatchDisabled(patchPath: string, id: string, disabled: boolean): PatchWriteResult {
  const text = existsSync(patchPath) ? readFileSync(patchPath, 'utf8') : '# dsh profile patch layer\n'
  const { text: next, action } = applyPatchChange(text, id, disabled)
  if (next === text) return { action, changed: false }
  const backup = join(dirname(patchPath), `cordis.patch.yml.audit-bak-${Date.now()}`)
  copyFileSync(patchPath, backup)
  writeFileSync(patchPath, next, 'utf8')
  return { action, backup, changed: true }
}
