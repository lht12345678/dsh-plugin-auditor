/**
 * dsh-plugin-auditor — 极简 semver：解析、比较、区间满足（^ ~ >= <= > < =、x-range、||）。
 * 无法解析的区间返回 null，调用方按“不可验证”降级为警告。
 */

export interface Version {
  major: number
  minor: number
  patch: number
  pre: string[]
}

export function parseVersion(v: string): Version | null {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$/.exec(v.trim())
  if (!m) return null
  return {
    major: Number(m[1]),
    minor: Number(m[2] ?? 0),
    patch: Number(m[3] ?? 0),
    pre: m[4] ? m[4].split('.') : [],
  }
}

function cmpPre(a: string[], b: string[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i]
    const y = b[i]
    if (x === undefined) return -1
    if (y === undefined) return 1
    const xn = /^\d+$/.test(x)
    const yn = /^\d+$/.test(y)
    if (xn && yn) {
      const d = parseInt(x, 10) - parseInt(y, 10)
      if (d !== 0) return d < 0 ? -1 : 1
    } else if (xn) return -1
    else if (yn) return 1
    else if (x !== y) return x < y ? -1 : 1
  }
  return 0
}

export function compareVersion(a: Version, b: Version): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1
  if (a.pre.length === 0 && b.pre.length === 0) return 0
  if (a.pre.length === 0) return 1
  if (b.pre.length === 0) return -1
  return cmpPre(a.pre, b.pre)
}

function comparator(part: string, v: Version): boolean | null {
  if (part === '*' || part === 'x' || part === 'X' || part === '') return true
  const m = /^(>=|<=|>|<|=|\^|~)?(.*)$/.exec(part)
  if (!m) return null
  const op = m[1] || '='
  let raw = m[2].trim()
  if (/^[xX*]$/.test(raw)) return true
  if (/^[xX*]\./.test(raw)) return true
  raw = raw.replace(/\.([xX*])$/, '')
  if (/^[xX*]$/.test(raw)) return true
  const t = parseVersion(raw)
  if (!t) return null
  const d = compareVersion(v, t)
  switch (op) {
    case '=':
      return d === 0
    case '>':
      return d > 0
    case '<':
      return d < 0
    case '>=':
      return d >= 0
    case '<=':
      return d <= 0
    case '^': {
      if (v.major !== t.major) return v.major > t.major
      if (t.major > 0) return v.minor > t.minor || (v.minor === t.minor && v.patch >= t.patch)
      if (t.minor > 0) return v.minor === t.minor && v.patch >= t.patch
      return v.patch === t.patch
    }
    case '~': {
      if (v.major !== t.major) return v.major > t.major
      if (v.minor !== t.minor) return v.minor > t.minor
      return v.patch >= t.patch
    }
    default:
      return null
  }
}

/** range 是否满足 version；区间不可解析返回 null。 */
export function satisfies(version: string, range: string): boolean | null {
  const v = parseVersion(version)
  if (!v) return null
  for (const or of range.split('||')) {
    const parts = or.trim().split(/\s+/).filter(Boolean)
    if (parts.length === 0) continue
    let ok = true
    for (const part of parts) {
      const r = comparator(part, v)
      if (r === null) return null
      if (!r) {
        ok = false
        break
      }
    }
    if (ok) return true
  }
  return false
}
