/**
 * WorkBuddy 桌面 App 凭据解析（只读）。
 *
 * 与 DSH 版插件同源的方案：
 *  1. 桌面 App 把登录态写在 `CodeBuddyExtension/Data/Public/auth/workbuddy-desktop.info`；
 *  2. 5.6 起 token 字段不再是明文，而是 `$wbEncrypted` 信封（AES-256-GCM）；
 *  3. 密钥本身由桌面 App 的电子运行时持有，只能请它自己吐出来：
 *     用 ELECTRON_RUN_AS_NODE=1 拉起 WorkBuddy 的 exe，执行一段 `-e` 脚本，
 *     读 BLE binding `electron_browser_workbuddy_storage.loggerGet()`，
 *     得到 `{version:1, atRestSecretKey:<base64 32B>}`；
 *  4. key = sha256(atRestSecretKey)，keyId = sha256(key).hex 前 16 位，
 *     必须与信封里的 keyId 一致才允许解密。
 *
 * 本模块绝不写桌面 App 的文件；续期后的 token 只存在插件自己的副本里。
 */

import { execFile } from 'node:child_process'
import { createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

/** 凭据刷新提前量：离过期不足 5 分钟就续。 */
const REFRESH_MARGIN_MS = 5 * 60 * 1000
/** 拉桌面 App 取密钥的超时。 */
const HELPER_TIMEOUT_MS = 15_000

/** 归一化后的凭据。 */
export interface WorkBuddyCredential {
  accessToken: string
  refreshToken: string
  /** 过期时间，epoch 毫秒。 */
  expiresAtMs: number
  refreshExpiresAtMs?: number
  domain: string
  uid: string
  enterpriseId?: string
  nickname?: string
}

/** 加密信封（app bundle 里的 `field` framing，suite 1）。 */
interface WrappedEnvelope {
  suite: number
  keyId: string
  nonce: Buffer
  authTag: Buffer
  ciphertext: Buffer
}

class CredentialError extends Error {
  constructor(readonly code: string, message: string) {
    super(message)
    this.name = 'CredentialError'
  }
}

// ---------------------------------------------------------------------------
// 1. 桌面 App 登录文件的位置
// ---------------------------------------------------------------------------

const AUTH_RELATIVE = ['CodeBuddyExtension', 'Data', 'Public', 'auth'] as const
const AUTH_FILENAME = 'workbuddy-desktop.info'

/** 环境变量可以显式指定登录文件位置。 */
const AUTH_FILE_ENV = 'WORKBUDDY_AUTH_FILE'

/** 各平台的候选路径，按探测顺序排列。 */
export function defaultAuthCandidates(): string[] {
  if (process.env[AUTH_FILE_ENV]?.trim()) return [process.env[AUTH_FILE_ENV]!.trim()]
  const home = homedir()
  const win = (root: string) => join(root, 'CodeBuddyExtension', 'Data', 'Public', 'auth', AUTH_FILENAME)
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA ?? join(home, 'AppData', 'Roaming')
    const localAppData = process.env.LOCALAPPDATA ?? join(home, 'AppData', 'Local')
    // 新版写 Local，旧版写 Roaming，两个都探。
    return [win(localAppData), win(appData)]
  }
  if (process.platform === 'darwin') {
    return [join(home, 'Library', 'Application Support', ...AUTH_RELATIVE, AUTH_FILENAME)]
  }
  const configHome = process.env.XDG_CONFIG_HOME ?? join(home, '.config')
  const dataHome = process.env.XDG_DATA_HOME ?? join(home, '.local', 'share')
  return [join(configHome, ...AUTH_RELATIVE, AUTH_FILENAME), join(dataHome, ...AUTH_RELATIVE, AUTH_FILENAME)]
}

// ---------------------------------------------------------------------------
// 2. 信封解密
// ---------------------------------------------------------------------------

/**
 * 信封的附加认证数据（AAD），照桌面 App bundle 里的
 * `buildAuthenticatedContextAad` 转写；凭据字段恒为 suite 1 / `WBEV1`。
 */
function buildAad(keyId: string, suite: number): Buffer {
  const lengthPrefixed = (value: string): Buffer => {
    const bytes = Buffer.from(value, 'utf8')
    const header = Buffer.allocUnsafe(4)
    header.writeUInt32BE(bytes.length)
    return Buffer.concat([header, bytes])
  }
  const suiteBytes = Buffer.allocUnsafe(4)
  suiteBytes.writeUInt32BE(suite)
  return Buffer.concat([
    Buffer.from('WB-AAD\0', 'ascii'),
    Buffer.from([1]),
    lengthPrefixed('WBEV1'),
    lengthPrefixed('sym-v1'),
    suiteBytes,
    lengthPrefixed(keyId),
    Buffer.from([2]),
    Buffer.from([0]),
    Buffer.from([0]),
  ])
}

/** 用保护密钥打开一个信封；打不开返回 undefined（绝不泄漏中间值）。 */
function openField(key: Buffer, envelope: WrappedEnvelope): string | undefined {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, envelope.nonce, { authTagLength: 16 })
    decipher.setAAD(buildAad(envelope.keyId, envelope.suite))
    decipher.setAuthTag(envelope.authTag)
    return Buffer.concat([decipher.update(envelope.ciphertext), decipher.final()]).toString('utf8')
  } catch {
    return undefined
  }
}

function parseBase64(value: unknown, length?: number): Buffer | undefined {
  if (typeof value !== 'string' || value === '') return undefined
  const decoded = Buffer.from(value, 'base64')
  if (decoded.length === 0) return undefined
  if (decoded.toString('base64').replace(/=+$/u, '') !== value.replace(/=+$/u, '')) return undefined
  return length === undefined || decoded.length === length ? decoded : undefined
}

/** 解析 `$wbEncrypted` 包装字段。非该包装返回 undefined。 */
function parseWrappedField(value: unknown): WrappedEnvelope | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  const wrapped = value as Record<string, unknown>
  if (wrapped.$wbEncrypted !== 1 || typeof wrapped.envelope !== 'string') return undefined
  let inner: unknown
  try {
    inner = JSON.parse(Buffer.from(wrapped.envelope, 'base64').toString('utf8'))
  } catch {
    return undefined
  }
  if (typeof inner !== 'object' || inner === null || Array.isArray(inner)) return undefined
  const parts = inner as Record<string, unknown>
  const nonce = parseBase64(parts.nonce, 12)
  const authTag = parseBase64(parts.authTag, 16)
  const ciphertext = parseBase64(parts.ciphertext)
  if (!nonce || !authTag || !ciphertext) return undefined
  if (parts.suite !== 1) return undefined
  if (typeof parts.keyId !== 'string' || !/^[0-9a-f]{16}$/u.test(parts.keyId)) return undefined
  return { suite: parts.suite as number, keyId: parts.keyId, nonce, authTag, ciphertext }
}

/** 负责把 at-rest 密钥从桌面 App 里取出来。 */
class AtRestKeyProvider {
  private cached: { key: Buffer; keyId: string } | undefined
  private inflight: Promise<{ key: Buffer; keyId: string }> | undefined
  private explicit = process.env.WORKBUDDY_ELECTRON_BIN?.trim() || undefined

  /** 候选 exe：显式指定优先，否则按常见安装位置猜。 */
  private async candidates(): Promise<string[]> {
    if (this.explicit) return [this.explicit]
    const found: string[] = []
    const localAppData = process.env.LOCALAPPDATA ?? ''
    const drives = ['C', process.env.SystemDrive?.slice(0, 1) ?? 'C', 'D', 'E']
    for (const drive of new Set(drives)) {
      if (!drive) continue
      found.push(join(`${drive}:`, 'Program Files', 'WorkBuddy', 'WorkBuddy.exe'))
      found.push(join(`${drive}:`, 'Program Files (x86)', 'WorkBuddy', 'WorkBuddy.exe'))
    }
    if (localAppData) found.push(join(localAppData, 'Programs', 'WorkBuddy', 'WorkBuddy.exe'))
    // macOS
    found.push('/Applications/WorkBuddy.app/Contents/MacOS/Electron')
    // 最后兜底：翻 Windows 卸载记录里的 DisplayIcon
    for (const path of await this.registryHints()) found.push(path)
    return [...new Set(found)]
  }

  /** 卸载表里名为 WorkBuddy 的 DisplayIcon，best-effort。 */
  private async registryHints(): Promise<string[]> {
    if (process.platform !== 'win32') return []
    const roots = [
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
    ]
    const hits: string[] = []
    for (const root of roots) {
      try {
        const { stdout } = await execFileAsync('reg', ['query', root, '/s', '/v', 'DisplayIcon'], {
          timeout: 4000, maxBuffer: 4 * 1024 * 1024, windowsHide: true,
        })
        let named = false
        for (const line of stdout.split(/\r?\n/u)) {
          const trimmed = line.trim()
          if (trimmed.startsWith('HKEY_')) { named = false; continue }
          const name = /^DisplayName\s+REG_SZ\s+(.+)$/iu.exec(trimmed)
          if (name) { named = /^WorkBuddy(?:\s+\d+(?:\.\d+)+)?$/iu.test(name[1]!.trim()); continue }
          const icon = /^DisplayIcon\s+REG_SZ\s+(.+)$/iu.exec(trimmed)
          if (named && icon) {
            const cleaned = icon[1]!.trim().replace(/^"|"$/gu, '').replace(/,\d+$/u, '')
            if (cleaned.toLowerCase().endsWith('.exe')) hits.push(cleaned)
          }
        }
      } catch {
        // 注册表不存在/无权限，忽略
      }
    }
    return hits
  }

  private async isExecutable(path: string): Promise<boolean> {
    try {
      const info = await stat(path)
      return info.isFile()
    } catch {
      return false
    }
  }

  /** 取 key，并校验它是否与信封里的 keyId 对得上。 */
  async keyFor(requested: readonly string[]): Promise<Buffer> {
    if (requested.length === 0) throw new CredentialError('encrypted-credential-unreadable', '信封里没有 keyId')
    if (this.cached && requested.includes(this.cached.keyId)) return this.cached.key
    this.inflight ??= this.spawn().finally(() => { this.inflight = undefined })
    const resolved = await this.inflight
    if (!requested.includes(resolved.keyId)) {
      throw new CredentialError(
        'encrypted-credential-unreadable',
        `当前 WorkBuddy 的 at-rest 密钥 id ${resolved.keyId} 与登录文件的 ${requested.join(' / ')} 不一致，`
        + '这段登录态应该是另一个安装写下的；请打开一次 WorkBuddy 让它重新保存',
      )
    }
    return resolved.key
  }

  private async spawn(): Promise<{ key: Buffer; keyId: string }> {
    const errors: string[] = []
    for (const path of await this.candidates()) {
      if (!(await this.isExecutable(path))) continue
      try {
        const text = await this.spawnAt(path)
        const payload = JSON.parse(text) as Record<string, unknown>
        if (payload.version !== 1 || typeof payload.atRestSecretKey !== 'string') continue
        const secret = Buffer.from(payload.atRestSecretKey as string, 'base64')
        if (secret.length !== 32 || secret.every(byte => byte === 0)) continue
        const key = createHash('sha256').update(payload.atRestSecretKey as string, 'utf8').digest()
        const resolved = { key, keyId: createHash('sha256').update(key).digest('hex').slice(0, 16) }
        this.cached = resolved
        return resolved
      } catch (error) {
        errors.push(`${path}: ${String(error)}`)
      }
    }
    throw new CredentialError(
      'electron-binary-unavailable',
      `没能从 WorkBuddy 桌面 App 取到密钥。用环境变量 WORKBUDDY_ELECTRON_BIN 指向它的可执行文件`
      + `（已试过默认安装位置${errors.length > 0 ? `：${errors.join('; ')}` : ''}）`,
    )
  }

  private async spawnAt(electronPath: string): Promise<string> {
    const script = 'process.stdout.write(String(process._linkedBinding("electron_browser_workbuddy_storage").loggerGet()))'
    const { stdout } = await execFileAsync(electronPath, ['-e', script], {
      timeout: HELPER_TIMEOUT_MS, maxBuffer: 1024 * 1024, windowsHide: true,
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
    })
    const text = stdout.trim()
    if (text === '') throw new Error('密钥助手没有输出')
    return text
  }
}

// ---------------------------------------------------------------------------
// 3. 登录文件 → 凭据
// ---------------------------------------------------------------------------

const keyProvider = new AtRestKeyProvider()

/** 秒或毫秒的时间戳统一成毫秒。 */
function expiryToMs(value: number): number {
  if (value <= 0) return 0
  return value > 1e12 ? value : value * 1000
}

/** 解析登录文档（明文形状，或已经解开了信封的形状）。 */
function parseAuthDocument(text: string): WorkBuddyCredential | undefined {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return undefined
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined
  const document = parsed as Record<string, unknown>
  const auth = (typeof document.auth === 'object' && document.auth !== null
    ? document.auth
    : document) as Record<string, unknown>
  const identity = (typeof document.account === 'object' && document.account !== null
    ? document.account
    : document) as Record<string, unknown>
  const accessToken = typeof auth.accessToken === 'string' ? auth.accessToken : ''
  if (accessToken === '') return undefined
  const pick = (source: Record<string, unknown>, key: string): string | undefined =>
    typeof source[key] === 'string' && (source[key] as string) !== '' ? source[key] as string : undefined
  const refreshExpiresAtMs = typeof auth.refreshExpiresAt === 'number' ? expiryToMs(auth.refreshExpiresAt) : undefined
  return {
    accessToken,
    refreshToken: typeof auth.refreshToken === 'string' ? auth.refreshToken : '',
    expiresAtMs: typeof auth.expiresAt === 'number' ? expiryToMs(auth.expiresAt) : 0,
    ...(refreshExpiresAtMs === undefined ? {} : { refreshExpiresAtMs }),
    domain: pick(auth, 'domain') ?? '',
    uid: pick(identity, 'uid') ?? '',
    ...(pick(identity, 'enterpriseId') === undefined ? {} : { enterpriseId: pick(identity, 'enterpriseId') }),
    ...(pick(identity, 'nickname') === undefined ? {} : { nickname: pick(identity, 'nickname') }),
  }
}

/** 读出登录文件；必要时先解信封。 */
async function readDesktop(): Promise<WorkBuddyCredential | undefined> {
  for (const path of defaultAuthCandidates()) {
    let text: string
    try {
      text = await readFile(path, 'utf8')
    } catch {
      continue
    }
    if (text.trim() === '') continue
    const direct = parseAuthDocument(text)
    if (direct !== undefined) return direct
    // token 字段被加密：找出所有信封，取密钥逐个解开。
    let parsed: Record<string, unknown>
    try {
      parsed = JSON.parse(text) as Record<string, unknown>
    } catch {
      continue
    }
    const auth = (typeof parsed.auth === 'object' && parsed.auth !== null ? parsed.auth : parsed) as Record<string, unknown>
    const envelopes = new Map<string, WrappedEnvelope>()
    for (const field of ['accessToken', 'refreshToken'] as const) {
      const envelope = parseWrappedField(auth[field])
      if (envelope) envelopes.set(field, envelope)
    }
    if (envelopes.size === 0) continue
    const key = await keyProvider.keyFor([...envelopes.values()].map(envelope => envelope.keyId))
    const rebuilt = structuredClone(parsed) as Record<string, unknown>
    const rebuiltAuth = (typeof rebuilt.auth === 'object' && rebuilt.auth !== null ? rebuilt.auth : rebuilt) as Record<string, unknown>
    for (const [field, envelope] of envelopes) {
      const plaintext = openField(key, envelope)
      if (plaintext === undefined) {
        throw new CredentialError(
          'encrypted-credential-unreadable',
          `登录文件的 ${field} 解不开（信封 keyId ${envelope.keyId}）；打开一次 WorkBuddy 让它重新保存登录态`,
        )
      }
      rebuiltAuth[field] = plaintext
    }
    const credential = parseAuthDocument(JSON.stringify(rebuilt))
    if (credential !== undefined) return credential
  }
  return undefined
}

// ---------------------------------------------------------------------------
// 4. 凭据仓库：读取 + 按需续期（只写自己的副本）
// ---------------------------------------------------------------------------

/** 插件自己的副本目录：`~/.pi/agent/workbuddy-connect/`。 */
export function stateDir(): string {
  const home = homedir()
  return join(process.env.PI_AGENT_HOME ?? join(home, '.pi', 'agent'), 'workbuddy-connect')
}

/** token 续期的传输层，由 upstream 注入，让本模块不依赖具体接口地址。 */
export interface RefreshTransport {
  (credential: WorkBuddyCredential): Promise<{
    accessToken: string
    refreshToken?: string
    expiresInSec?: number
    domain?: string
  }>
}

export class CredentialStore {
  private inflight: Promise<WorkBuddyCredential> | undefined
  private readonly ownPath: string

  constructor(private readonly refreshTokenUpstream: RefreshTransport) {
    this.ownPath = join(stateDir(), 'auth.json')
  }

  /** 自己的副本路径，给诊断用。 */
  ownAuthPath(): string {
    return this.ownPath
  }

  /** 当前登录文件路径，给诊断用。 */
  desktopAuthPath(): string {
    return defaultAuthCandidates()[0] ?? '(未知)'
  }

  private async readOwn(): Promise<WorkBuddyCredential | undefined> {
    try {
      const parsed = JSON.parse(await readFile(this.ownPath, 'utf8')) as Record<string, unknown>
      if (parsed.version !== 1 || typeof parsed.credential !== 'object' || parsed.credential === null) return undefined
      const stored = parsed.credential as Record<string, unknown>
      if (typeof stored.accessToken !== 'string' || stored.accessToken === '') return undefined
      const pick = (key: string): string | undefined =>
        typeof stored[key] === 'string' && (stored[key] as string) !== '' ? stored[key] as string : undefined
      return {
        accessToken: stored.accessToken,
        refreshToken: typeof stored.refreshToken === 'string' ? stored.refreshToken : '',
        expiresAtMs: typeof stored.expiresAtMs === 'number' ? stored.expiresAtMs : 0,
        ...(typeof stored.refreshExpiresAtMs === 'number' ? { refreshExpiresAtMs: stored.refreshExpiresAtMs } : {}),
        domain: pick('domain') ?? '',
        uid: pick('uid') ?? '',
        ...(pick('enterpriseId') === undefined ? {} : { enterpriseId: pick('enterpriseId') }),
        ...(pick('nickname') === undefined ? {} : { nickname: pick('nickname') }),
      }
    } catch {
      return undefined
    }
  }

  private async saveOwn(credential: WorkBuddyCredential): Promise<void> {
    await mkdir(dirname(this.ownPath), { recursive: true, mode: 0o700 })
    await writeFile(this.ownPath, `${JSON.stringify({ version: 1, credential }, null, 2)}\n`, { mode: 0o600 })
  }

  /** 当前有效凭据，不触发续期。桌面文件的身份永远优先于副本。 */
  async current(): Promise<WorkBuddyCredential | undefined> {
    const [desktop, own] = await Promise.all([readDesktop(), this.readOwn()])
    if (!desktop) return own
    if (!own) return desktop
    // 换了账号身份说了算：副本可能还是上一个账号、且刚被续过期。
    if (desktop.uid !== own.uid || desktop.enterpriseId !== own.enterpriseId) return desktop
    return own.expiresAtMs > desktop.expiresAtMs ? own : desktop
  }

  /** 取一份可以直接发上游的凭据（临近过期时自动续期，单飞）。 */
  async resolve(): Promise<WorkBuddyCredential> {
    const credential = await this.current()
    if (!credential) {
      throw new CredentialError(
        'no-credential',
        `没有可用的 WorkBuddy 登录态；请先打开 WorkBuddy 桌面 App 登录一次（期望位置 ${this.desktopAuthPath()}）`,
      )
    }
    const needsRefresh = credential.expiresAtMs <= 0 || Date.now() + REFRESH_MARGIN_MS >= credential.expiresAtMs
    if (!needsRefresh) return credential
    this.inflight ??= this.refreshNow(credential).finally(() => { this.inflight = undefined })
    return this.inflight
  }

  private async refreshNow(credential: WorkBuddyCredential): Promise<WorkBuddyCredential> {
    const stillValid = credential.expiresAtMs > Date.now() + 30_000
    if (credential.refreshToken === '') {
      if (stillValid) return credential
      throw new CredentialError('no-refresh-token', 'access token 已过期且没有 refresh token，请在 WorkBuddy 里重新登录')
    }
    try {
      const outcome = await this.refreshTokenUpstream(credential)
      const refreshed: WorkBuddyCredential = {
        ...credential,
        accessToken: outcome.accessToken,
        ...(outcome.refreshToken === undefined ? {} : { refreshToken: outcome.refreshToken }),
        expiresAtMs: outcome.expiresInSec !== undefined
          ? Date.now() + outcome.expiresInSec * 1000
          : credential.expiresAtMs,
        ...(outcome.domain === undefined || outcome.domain === '' ? {} : { domain: outcome.domain }),
      }
      await this.saveOwn(refreshed)
      return refreshed
    } catch (error) {
      if (stillValid) return credential
      throw new CredentialError('refresh-failed', `token 续期失败且旧 token 已过期（${String(error)}）；请打开一次 WorkBuddy`)
    }
  }

  /** 清掉自己的副本；桌面 App 的登录态不动。 */
  async logout(): Promise<void> {
    await rm(this.ownPath, { force: true })
  }
}

/** 供 state 目录初始化使用。 */
export async function ensureStateDir(): Promise<void> {
  await mkdir(stateDir(), { recursive: true, mode: 0o700 })
}

/** 生成一次性的 loopback 共享密钥。 */
export function newShimToken(): string {
  return randomBytes(24).toString('hex')
}
