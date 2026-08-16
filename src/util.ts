/**
 * dsh-plugin-auditor — 基础设施：路径、指纹、冒烟加载、版本解析辅助。
 */
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { spawn, spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

export const AUDITOR_VERSION = '0.2.0'

/** 从进程 argv 解析当前 profile（与 dsh-market 同款）。 */
export function argvProfile(): string | undefined {
  const argv = process.argv
  const flag = argv.indexOf('--profile')
  if (flag !== -1 && flag + 1 < argv.length && !argv[flag + 1].startsWith('-')) return argv[flag + 1]
  return undefined
}

export function profileDir(): string {
  return join(homedir(), '.dsh', 'profiles', argvProfile() ?? 'web')
}

export function auditorHome(): string {
  return join(homedir(), '.dsh', 'plugin-auditor')
}

export function ensureDir(p: string): void {
  mkdirSync(p, { recursive: true })
}

export function readJsonFile(p: string): any | undefined {
  try {
    const raw = readFileSync(p, 'utf8')
    return JSON.parse(raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw)
  } catch {
    return undefined
  }
}

export function writeJsonFile(p: string, v: unknown): void {
  ensureDir(dirname(p))
  writeFileSync(p, JSON.stringify(v, null, 2), 'utf8')
}

/** 从某个基准目录解析模块（候选目录 / profile node_modules / host node_modules）。 */
export function resolveFrom(baseDir: string, spec: string): string | undefined {
  try {
    return createRequire(join(baseDir, '__probe__.cjs')).resolve(spec)
  } catch {
    // CJS resolve 对 ESM-only exports（仅 import 条件）会失败 → 退化为存在性探测
    const p = existsProbe(baseDir, spec)
    return p
  }
}

/**
 * 存在性探测：baseDir/node_modules/<spec> 或 baseDir/<spec> 是否存在。
 * baseDir 可能是包目录（Node 语义）也可能是 node_modules 目录本身（profile/host 直查），
 * 两个位置都试。覆盖 pnpm 顶层 symlink 布局与 ESM-only 包（require.resolve 无法解析的场景）。
 */
function existsProbe(baseDir: string, spec: string): string | undefined {
  const segs = spec.split('/')
  for (const root of [join(baseDir, 'node_modules'), baseDir]) {
    let p = root
    let ok = true
    for (const seg of segs) {
      p = join(p, seg)
      if (!existsSync(p)) {
        ok = false
        break
      }
    }
    if (ok) return p
  }
  return undefined
}

/** 全链路解析：profile nm → host nm → @deepseek-ai/ 前缀兜底（DSH 的 scoped 化约定）。 */
export function resolveAny(spec: string): string | undefined {
  const bases = [join(profileDir(), 'node_modules'), hostNodeModules()]
  for (const b of bases) {
    const r = resolveFrom(b, spec)
    if (r) return r
    if (!spec.startsWith('@')) {
      const r2 = resolveFrom(b, '@deepseek-ai/' + spec)
      if (r2) return r2
    }
  }
  return undefined
}

const _req = createRequire(import.meta.url)

/** 定位宿主 node_modules（@deepseek-ai/dsh-tools 的上级两级）。 */
export function hostNodeModules(): string {
  try {
    return resolve(dirname(dirname(dirname(_req.resolve('@deepseek-ai/dsh-tools')))))
  } catch {
    return join(profileDir(), 'node_modules')
  }
}

export function isCore(name: string, prefixes: string[]): boolean {
  if (!name) return false
  if (prefixes.some((p) => name.startsWith(p))) return true
  return name.startsWith('./') || name.startsWith('../') || name.startsWith('node:') || name.startsWith('file:')
}

/** 目录内容指纹：排序路径 + 大小 + 内容 hash（跳过 node_modules/.git）。 */
export function fingerprintDir(dir: string): string {
  const hash = createHash('sha256')
  const walk = (d: string, prefix: string): void => {
    let entries: string[] = []
    try {
      entries = readdirSync(d)
    } catch {
      return
    }
    entries.sort()
    for (const e of entries) {
      if (e === 'node_modules' || e === '.git') continue
      const full = join(d, e)
      let st
      try {
        st = statSync(full)
      } catch {
        continue
      }
      if (st.isDirectory()) walk(full, prefix + e + '/')
      else if (st.isFile()) {
        hash.update(prefix + e)
        hash.update(String(st.size))
        if (st.size < 2 * 1024 * 1024) {
          try {
            hash.update(readFileSync(full))
          } catch {
            /* 跳过不可读 */
          }
        }
      }
    }
  }
  walk(dir, '')
  return hash.digest('hex')
}

/** node --check 语法检查；返回 null 表示通过，否则返回错误摘要。 */
export function nodeCheck(file: string, timeoutMs: number): string | null {
  try {
    const r = spawnSync(process.execPath, ['--check', file], {
      encoding: 'utf8',
      timeout: timeoutMs,
      windowsHide: true,
    })
    if (r.status === 0) return null
    return String(r.stderr || r.stdout || 'syntax check failed').slice(0, 400)
  } catch (e) {
    return String(e).slice(0, 400)
  }
}

/**
 * 子进程冒烟加载：验证入口可被 ESM import 且导出 apply()。
 * 隔离在子进程内，顶层副作用与崩溃不会波及 harness 本身。
 */
export function smokeImport(
  file: string,
  timeoutMs: number,
): Promise<{ ok: boolean; error?: string; name?: string }> {
  return new Promise((resolvePromise) => {
    const url = pathToFileURL(file).href
    const code =
      `const u=process.argv[1];try{const m=await import(u);` +
      `const a=m.apply??m.default?.apply;if(typeof a!=='function'){` +
      `console.error('NO_APPLY:'+(m.name??'?'));process.exit(2)}` +
      `console.log('OK:'+(m.name??'?'))}catch(e){console.error('ERR:'+(e?.message??String(e)));process.exit(3)}`
    const child = spawn(process.execPath, ['--input-type=module', '-e', code, url], {
      cwd: dirname(file),
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
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
      resolvePromise({ ok: false, error: String(e).slice(0, 300) })
    })
    child.on('exit', (code) => {
      clearTimeout(timer)
      if (code === 0) resolvePromise({ ok: true, name: out.trim().replace(/^OK:/, '') })
      else if (code === 2)
        resolvePromise({ ok: false, error: `入口未导出 apply()（模块名=${out.trim().replace(/^NO_APPLY:/, '') || '?'}）` })
      else if (code === 3) resolvePromise({ ok: false, error: `加载异常: ${(err || out).trim().slice(0, 500)}` })
      else if (code === null) resolvePromise({ ok: false, error: `加载超时（>${timeoutMs}ms，已终止）` })
      else resolvePromise({ ok: false, error: `加载失败 code=${code}: ${err.trim().slice(0, 300)}` })
    })
  })
}

/** 读取已解析包的 version（用于 peer 冲突比对）。 */
export function installedVersion(resolvedPath: string): string | undefined {
  let dir = resolvedPath
  if (statSync(resolvedPath, { throwIfNoEntry: false })?.isFile()) dir = dirname(resolvedPath)
  let cur = dir
  for (let i = 0; i < 6; i++) {
    const pkg = readJsonFile(join(cur, 'package.json'))
    if (pkg?.version) return String(pkg.version)
    const next = dirname(cur)
    if (next === cur) break
    cur = next
  }
  return undefined
}
