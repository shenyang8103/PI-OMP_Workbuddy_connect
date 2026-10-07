/**
 * WorkBuddy 上游接口：模型目录、对话转发、token 续期、积分查询。
 *
 * 三个端点，按 region 选择基地址：
 *  - CN：https://copilot.tencent.com    （对话 / 续期 / 目录）
 *         https://www.codebuddy.cn      （积分）
 *  - 国际：https://www.workbuddy.ai
 *
 * 请求头里那些 X-* 是上游网关认客户身份的依据，缺了会被当成非法调用。
 */

import type { WorkBuddyCredential } from './credential.ts'

const CN_CHAT_BASE = 'https://copilot.tencent.com'
const CN_BILLING_BASE = 'https://www.codebuddy.cn'
const GLOBAL_BASE = 'https://www.workbuddy.ai'

/** 目录请求要装成官方 CLI 的样子，网关按 UA 分流这道名单。 */
const CLIENT_UA = 'CLI/2.63.2 CodeBuddy/2.63.2'
/** 对话请求要装成桌面客户端的样子。 */
const FALLBACK_APP_VERSION = '5.5.6'

const JSON_TIMEOUT_MS = 30_000
/** 错误回执最多保留这么多字节给上层看。 */
const ERROR_BODY_LIMIT = 2048

/** 地区判定：空 domain 视为 CN。 */
export function regionOf(domain: string): 'cn' | 'global' {
  const lowered = domain.trim().toLowerCase()
  return lowered === 'workbuddy.ai' || lowered.endsWith('.workbuddy.ai') ? 'global' : 'cn'
}

function chatBase(credential: WorkBuddyCredential): string {
  return regionOf(credential.domain) === 'global' ? GLOBAL_BASE : CN_CHAT_BASE
}

function billingBase(credential: WorkBuddyCredential): string {
  return regionOf(credential.domain) === 'global' ? GLOBAL_BASE : CN_BILLING_BASE
}

function originOf(credential: WorkBuddyCredential): string {
  return regionOf(credential.domain) === 'global' ? GLOBAL_BASE : CN_BILLING_BASE
}

function commonHeaders(credential: WorkBuddyCredential): Record<string, string> {
  const origin = originOf(credential)
  return {
    'Accept': 'application/json, text/plain, */*',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': origin,
    'Referer': `${origin}/`,
  }
}

/** 对话请求头。安全红线：绝不带 refresh token。 */
function chatHeaders(credential: WorkBuddyCredential): Record<string, string> {
  const region = regionOf(credential.domain)
  const version = FALLBACK_APP_VERSION
  const product = region === 'global' ? 'WorkBuddy AI' : 'WorkBuddy'
  return {
    ...commonHeaders(credential),
    'Content-Type': 'application/json',
    'User-Agent': `WorkBuddy/${version} ${product}/${version}`,
    ...(credential.uid === '' ? { 'X-No-User-Id': '1' } : { 'X-User-Id': credential.uid }),
    ...(credential.enterpriseId === undefined || credential.enterpriseId === ''
      ? { 'X-No-Enterprise-Id': '1' }
      : { 'X-Enterprise-Id': credential.enterpriseId }),
    ...(credential.domain === '' ? { 'X-No-Department-Info': '1' } : { 'X-Domain': credential.domain }),
    'X-IDE-Type': 'WorkBuddy',
    'X-IDE-Name': 'WorkBuddy',
    'X-IDE-Version': version,
    'X-Product': 'SaaS',
    'Authorization': `Bearer ${credential.accessToken}`,
  }
}

// ---------------------------------------------------------------------------
// 模型目录
// ---------------------------------------------------------------------------

/** 上游声明的推理档位。 */
export type WorkBuddyEffort = 'low' | 'medium' | 'high' | 'xhigh' | 'max'

const EFFORT_VALUES: readonly string[] = ['low', 'medium', 'high', 'xhigh', 'max']

export interface WorkBuddyModel {
  id: string
  name: string
  contextWindow: number
  maxTokens: number
  supportsImages: boolean
  reasoning: {
    supports: boolean
    supportedEfforts?: WorkBuddyEffort[]
    defaultEffort?: WorkBuddyEffort
    canDisableThinking: boolean
  }
  /** 计费倍率，形如 `x0.29`；仅用于展示。 */
  credits?: string
}

function rowsOf(data: Record<string, unknown>): Record<string, unknown>[] {
  const raw = data.models
  if (Array.isArray(raw)) return raw.filter(row => typeof row === 'object' && row !== null) as Record<string, unknown>[]
  // /v3/config 实测返回的是按下标索引的对象，不是数组。
  if (typeof raw === 'object' && raw !== null) return Object.values(raw as Record<string, unknown>)
    .filter(row => typeof row === 'object' && row !== null) as Record<string, unknown>[]
  return []
}

/** 从产品文档里挑出 cli 名单 ∩ 可用行。 */
export function parseCatalog(data: Record<string, unknown>): WorkBuddyModel[] {
  const agents = Array.isArray(data.agents) ? data.agents : []
  let cliIds: string[] | undefined
  for (const agent of agents) {
    if (typeof agent !== 'object' || agent === null) continue
    const wrapped = agent as Record<string, unknown>
    if (wrapped.name === 'cli' && Array.isArray(wrapped.models)) {
      cliIds = wrapped.models.filter((id): id is string => typeof id === 'string')
      break
    }
  }
  if (cliIds === undefined || cliIds.length === 0) throw new Error('WorkBuddy 目录里没有 cli 名单')

  const byId = new Map<string, WorkBuddyModel>()
  for (const row of rowsOf(data)) {
    const id = typeof row.id === 'string' ? row.id : ''
    const input = typeof row.maxInputTokens === 'number' ? row.maxInputTokens : 0
    const output = typeof row.maxOutputTokens === 'number' ? row.maxOutputTokens : 0
    if (id === '' || row.disabled === true || input <= 0 || output <= 0) continue
    let supportedEfforts: WorkBuddyEffort[] | undefined
    let defaultEffort: WorkBuddyEffort | undefined
    let canDisableThinking = false
    const rawReasoning = row.reasoning
    if (typeof rawReasoning === 'object' && rawReasoning !== null) {
      const reasoning = rawReasoning as Record<string, unknown>
      if (Array.isArray(reasoning.supportedEfforts)) {
        const efforts = reasoning.supportedEfforts.filter(
          (value): value is WorkBuddyEffort => typeof value === 'string' && EFFORT_VALUES.includes(value),
        )
        if (efforts.length > 0) supportedEfforts = efforts
      }
      const declared = reasoning.defaultEffort ?? reasoning.effort
      if (typeof declared === 'string' && EFFORT_VALUES.includes(declared)) defaultEffort = declared as WorkBuddyEffort
      canDisableThinking = reasoning.canDisableThinking === true
    }
    byId.set(id, {
      id,
      name: typeof row.name === 'string' && row.name !== '' ? row.name : id,
      contextWindow: input,
      maxTokens: output,
      supportsImages: row.supportsImages === true && row.disabledMultimodal !== true,
      reasoning: {
        supports: row.supportsReasoning === true,
        ...(supportedEfforts === undefined ? {} : { supportedEfforts }),
        ...(defaultEffort === undefined ? {} : { defaultEffort }),
        canDisableThinking,
      },
      ...(typeof row.credits === 'string' && row.credits.trim() !== ''
        ? { credits: row.credits.trim().replace(/\s+credits?$/iu, '').trim() }
        : {}),
    })
  }
  return cliIds.map(id => byId.get(id)).filter((model): model is WorkBuddyModel => model !== undefined)
}

/** 解开 `{code,msg,data}` 信封；也兼容产品文档直接裸回。 */
async function readDocument(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text()
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error(`WorkBuddy 返回了非 JSON（http ${response.status}）：${text.slice(0, 160)}`)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`WorkBuddy 返回了意外的文档（http ${response.status}）`)
  }
  const document = parsed as Record<string, unknown>
  const code = typeof document.code === 'number' ? document.code : 0
  const msg = typeof document.msg === 'string' ? document.msg : ''
  if (!response.ok || code !== 0) {
    throw new Error(`WorkBuddy 上游报错（http ${response.status}）：${msg.slice(0, 200) || text.slice(0, 200)}`)
  }
  const data = document.data
  if (typeof data === 'object' && data !== null) return data as Record<string, unknown>
  if ('models' in document || 'agents' in document) return document
  throw new Error('WorkBuddy 目录文档里没有内容')
}

/** 拉一次模型目录。 */
export async function fetchModels(credential: WorkBuddyCredential, signal?: AbortSignal): Promise<WorkBuddyModel[]> {
  const response = await fetch(`${chatBase(credential)}/v3/config`, {
    headers: { ...commonHeaders(credential), 'Authorization': `Bearer ${credential.accessToken}`, 'User-Agent': CLIENT_UA },
    signal: signal ?? AbortSignal.timeout(JSON_TIMEOUT_MS),
  })
  return parseCatalog(await readDocument(response))
}

// ---------------------------------------------------------------------------
// 对话转发
// ---------------------------------------------------------------------------

/** 成功后返回原始 SSE 响应；失败返回结构化错误。 */
export type ChatResult =
  | { ok: true; response: Response }
  | { ok: false; status: number; message: string }

/**
 * 把 OpenAI 形状的 body 改成上游能吃的样子：
 *  - 强制 stream（上游不接受非流式）；
 *  - `developer` 角色改写成 `system`（上游会报渠道非法）；
 *  - `tool_choice` 对象拍平成字符串，值为 none 时把工具一起删掉。
 */
export function prepareBody(source: string): string {
  let body: unknown
  try {
    body = JSON.parse(source)
  } catch {
    return source
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return source
  const obj = body as Record<string, unknown>
  obj.stream = true
  const messages = obj.messages
  if (Array.isArray(messages)) {
    for (const message of messages) {
      if (typeof message !== 'object' || message === null || Array.isArray(message)) continue
      const wrapped = message as Record<string, unknown>
      if (wrapped.role === 'developer') wrapped.role = 'system'
    }
  }
  normalizeToolChoice(obj)
  return JSON.stringify(obj)
}

function normalizeToolChoice(obj: Record<string, unknown>): void {
  const suppress = (): void => {
    delete obj.tools
    delete obj.functions
  }
  if (!('tool_choice' in obj)) return
  const choice = obj.tool_choice
  if (typeof choice === 'string') {
    if (choice.trim().toLowerCase() === 'none') {
      delete obj.tool_choice
      suppress()
    }
    return
  }
  if (typeof choice === 'object' && choice !== null && !Array.isArray(choice)) {
    const wrapped = choice as Record<string, unknown>
    const type = typeof wrapped.type === 'string' ? wrapped.type.trim().toLowerCase() : ''
    if (type === 'none') {
      delete obj.tool_choice
      suppress()
    } else if (type === 'auto' || type === 'required') {
      obj.tool_choice = type
    } else if (type === 'function') {
      const fn = typeof wrapped.function === 'object' && wrapped.function !== null
        ? wrapped.function as Record<string, unknown>
        : undefined
      const rawName = (typeof fn?.name === 'string' ? fn.name : typeof wrapped.name === 'string' ? wrapped.name : '').trim()
      obj.tool_choice = rawName !== '' ? rawName : 'auto'
    } else {
      delete obj.tool_choice
    }
    return
  }
  delete obj.tool_choice
}

/** 发一条对话。 */
export async function chat(credential: WorkBuddyCredential, bodyJson: string, signal?: AbortSignal): Promise<ChatResult> {
  let response: Response
  try {
    response = await fetch(`${chatBase(credential)}/v2/chat/completions`, {
      method: 'POST',
      headers: chatHeaders(credential),
      body: prepareBody(bodyJson),
      ...(signal === undefined ? {} : { signal }),
    })
  } catch (error) {
    return { ok: false, status: 0, message: `网络错误：${String(error)}` }
  }
  if (response.ok) return { ok: true, response }
  const text = (await response.text()).slice(0, ERROR_BODY_LIMIT)
  return { ok: false, status: response.status, message: pickUpstreamMessage(text) }
}

/** 优先展示上游本地化的文案，其次 msg。 */
function pickUpstreamMessage(body: string): string {
  const trimmed = body.trim()
  if (!trimmed.startsWith('{')) return trimmed.slice(0, 300)
  try {
    const obj = JSON.parse(trimmed) as Record<string, unknown>
    const display = obj.displayMsg
    if (typeof display === 'object' && display !== null) {
      const localized = display as Record<string, unknown>
      for (const key of ['zh', 'en']) {
        if (typeof localized[key] === 'string' && (localized[key] as string).trim() !== '') return localized[key] as string
      }
    }
    if (typeof obj.msg === 'string' && obj.msg.trim() !== '') return obj.msg.trim()
  } catch {
    // 非 JSON 就原样返回
  }
  return trimmed.slice(0, 300)
}

// ---------------------------------------------------------------------------
// token 续期 / 积分
// ---------------------------------------------------------------------------

/** 用 refresh token 换新 access token。 */
export async function refreshToken(credential: WorkBuddyCredential): Promise<{
  accessToken: string
  refreshToken?: string
  expiresInSec?: number
  domain?: string
}> {
  const response = await fetch(`${chatBase(credential)}/v2/plugin/auth/token/refresh`, {
    method: 'POST',
    headers: {
      ...commonHeaders(credential),
      'User-Agent': CLIENT_UA,
      'X-Refresh-Token': credential.refreshToken,
      'X-Auth-Refresh-Source': 'workbuddy',
      ...(credential.enterpriseId === undefined || credential.enterpriseId === ''
        ? {}
        : { 'X-Enterprise-Id': credential.enterpriseId }),
    },
    signal: AbortSignal.timeout(JSON_TIMEOUT_MS),
  })
  const data = await readDocument(response)
  const accessToken = typeof data.accessToken === 'string' ? data.accessToken : ''
  if (accessToken === '') throw new Error('续期返回里没有 accessToken')
  return {
    accessToken,
    ...(typeof data.refreshToken === 'string' && data.refreshToken !== '' ? { refreshToken: data.refreshToken } : {}),
    ...(typeof data.expiresIn === 'number' && data.expiresIn > 0 ? { expiresInSec: data.expiresIn } : {}),
    ...(typeof data.domain === 'string' && data.domain !== '' ? { domain: data.domain } : {}),
  }
}

interface CreditAccount {
  name: string
  remains: number
  used: number
}

/** 查剩余额度；失败返回 undefined，不打扰主流程。 */
export async function fetchCredits(credential: WorkBuddyCredential): Promise<
  { accounts: CreditAccount[]; totalRemain: number } | undefined
> {
  try {
    const now = new Date()
    const stamp = (date: Date): string => {
      const day = [date.getFullYear(), date.getMonth() + 1, date.getDate()].map(n => String(n).padStart(2, '0')).join('-')
      const time = [date.getHours(), date.getMinutes(), date.getSeconds()].map(n => String(n).padStart(2, '0')).join(':')
      return `${day} ${time}`
    }
    const response = await fetch(`${billingBase(credential)}/v2/billing/meter/get-user-resource`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${credential.accessToken}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        ...(credential.uid !== '' ? { 'X-User-Id': credential.uid } : {}),
        ...(credential.domain !== '' ? { 'X-Domain': credential.domain } : {}),
      },
      body: JSON.stringify({
        PageNumber: 1,
        PageSize: 100,
        ProductCode: 'p_tcaca',
        Status: [0, 3],
        PackageEndTimeRangeBegin: stamp(now),
        PackageEndTimeRangeEnd: stamp(new Date(now.getTime() + 365 * 24 * 3600 * 1000)),
      }),
      signal: AbortSignal.timeout(JSON_TIMEOUT_MS),
    })
    const data = await readDocument(response)
    const inner = typeof data.Data === 'object' && data.Data !== null ? data.Data as Record<string, unknown> : data
    const raw = Array.isArray(inner.Accounts) ? inner.Accounts : []
    const accounts: CreditAccount[] = []
    let totalRemain = 0
    for (const item of raw) {
      if (typeof item !== 'object' || item === null) continue
      const row = item as Record<string, unknown>
      const number = (key: string): number => (typeof row[key] === 'number' ? row[key] as number : 0)
      const capacity = number('CapacityRemain')
      const cycleRemain = number('CycleCapacityRemain')
      const size = number('CycleCapacitySize')
      const remains = size > 0 ? cycleRemain : capacity
      const used = number('CycleCapacityUsed')
      totalRemain += remains
      accounts.push({
        name: typeof row.PackageName === 'string' ? row.PackageName : '(未命名)',
        remains,
        used,
      })
    }
    return { accounts, totalRemain }
  } catch {
    return undefined
  }
}
