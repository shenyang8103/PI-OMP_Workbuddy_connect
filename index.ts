/**
 * pi-workbuddy-connect —— 把 WorkBuddy 桌面 App 里含的模型接入 Pi。
 *
 * 思路与 DSH 上的 dsh-workbuddy-connect 完全一致，只是宿主换成 Pi：
 *   1. 读桌面 App 的登录文件（加密则用 App 自己的 Electron 取出 at-rest 密钥解开）；
 *   2. 起一个只对 127.0.0.1 监听的一次性回环服务（shim）负责翻译和转发；
 *   3. 向 Pi 注册一个 openai-completions provider，baseUrl 指向这个 shim，
 *      模型清单来自上游 /v3/config 的 cli 名单。
 *
 * 于是 `/model` 里能直接选到 WorkBuddy 的模型，流式、工具调用、 usage
 * 都由 Pi 内置的 OpenAI 实现接管，这里只做协议与身份的转换。
 */

import { randomBytes } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
// 兼容 Pi 与 oh-my-pi(omp) 的极简 ExtensionAPI 声明：
// 两个宿主的扩展 API 同源，这里只声明本插件实际用到的两个方法，
// 从而不依赖任一宿主的包名（@earendil-works/pi-coding-agent / @oh-my-pi/pi-coding-agent）。
interface ExtensionAPI {
  registerProvider(name: string, config: any): void
  registerCommand(name: string, config: {
    description: string
    handler: (args: string, ctx: any) => void | Promise<void>
  }): void
}
import { CredentialStore, stateDir, type WorkBuddyCredential } from './src/credential.ts'
import { startShim } from './src/shim.ts'
import { fetchCredits, fetchModels, refreshToken, type WorkBuddyModel } from './src/upstream.ts'

const PROVIDER_ID = 'workbuddy'
if (process.env.WORKBUDDY_DEBUG === '1') process.stderr.write('[workbuddy] module evaluated\n')
/** 目录快照，启动拉不到时兜底。 */
const CATALOG_CACHE = 'catalog.json'

const NO_COST = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }

/** Pi 的推理档位 → 上游 wire 拼写；null 表示这一档不可用。 */
function thinkingLevelMap(model: WorkBuddyModel): Record<string, string | null> {
  const efforts = model.reasoning.supportedEfforts
  return {
    off: model.reasoning.canDisableThinking ? 'off' : null,
    minimal: null,
    low: efforts?.includes('low') ? 'low' : null,
    medium: efforts?.includes('medium') ? 'medium' : null,
    high: efforts?.includes('high') ? 'high' : null,
    xhigh: efforts?.includes('xhigh') ? 'xhigh' : null,
    max: efforts?.includes('max') ? 'max' : null,
  }
}

/**
 * 是否开启推理档位控件。
 * 只有上游明确声明了 supportedEfforts 才敢发 reasoning_effort ——否则会拿到 400。
 */
function toModelConfig(model: WorkBuddyModel): Record<string, unknown> {
  const declared = model.reasoning.supportedEfforts
  const useReasoning = model.reasoning.supports && declared !== undefined && declared.length > 0
  return {
    id: model.id,
    name: model.credits === undefined ? model.name : `${model.name} · ${model.credits}`,
    input: model.supportsImages ? ['text', 'image'] : ['text'],
    cost: { ...NO_COST },
    reasoning: useReasoning,
    ...(useReasoning ? { thinkingLevelMap: thinkingLevelMap(model) } : {}),
    contextWindow: model.contextWindow,
    maxTokens: model.maxTokens,
    compat: {
      maxTokensField: 'max_tokens',
      supportsDeveloperRole: false,
      supportsReasoningEffort: model.reasoning.supports,
    },
  }
}

async function loadCachedCatalog(): Promise<WorkBuddyModel[]> {
  try {
    const parsed = JSON.parse(await readFile(join(stateDir(), CATALOG_CACHE), 'utf8')) as unknown
    if (!Array.isArray(parsed)) return []
    return parsed as WorkBuddyModel[]
  } catch {
    return []
  }
}

async function saveCatalog(models: readonly WorkBuddyModel[]): Promise<void> {
  const path = join(stateDir(), CATALOG_CACHE)
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  await writeFile(path, `${JSON.stringify(models, null, 2)}\n`, { mode: 0o600 })
}

export default async function (pi: ExtensionAPI): Promise<void> {
  const debug = process.env.WORKBUDDY_DEBUG === '1'
  const trace = (stage: string): void => {
    if (debug) process.stderr.write(`[workbuddy] ${stage}\n`)
  }
  trace('factory-enter')
  await mkdir(stateDir(), { recursive: true, mode: 0o700 })
  const store = new CredentialStore(refreshToken)
  const resolveCredential = (): Promise<WorkBuddyCredential> => store.resolve()

  // 启动就拿一次目录；失败就退回到上次的快照，保证离线也能开口说话。
  let models: WorkBuddyModel[] = []
  let catalogProblem: string | undefined
  try {
    models = await fetchModels(await store.resolve())
    await saveCatalog(models)
  } catch (error) {
    catalogProblem = error instanceof Error ? error.message : String(error)
    trace(`catalog failed: ${catalogProblem}`)
    models = await loadCachedCatalog()
  }
  trace(`models=${models.length}`)

  const shim = await startShim(randomBytes(24).toString('hex'), () => models, resolveCredential)
  trace(`shim=${shim.baseUrl()}`)

  pi.registerProvider(PROVIDER_ID, {
    name: 'WorkBuddy',
    baseUrl: shim.baseUrl(),
    apiKey: shim.token(),
    api: 'openai-completions',
    authHeader: true,
    models: models.map(toModelConfig) as never,
    refreshModels: async (context: { signal?: AbortSignal }) => {
      const credential = await store.resolve()
      const fresh = await fetchModels(credential, context?.signal)
      models = fresh
      await saveCatalog(fresh)
      return fresh.map(toModelConfig) as never
    },
  })

  pi.registerCommand('workbuddy', {
    description: '查看 WorkBuddy 连接状态与剩余额度',
    handler: async (_args: string, ctx: { ui: { notify: (message: string, level?: string) => void } }) => {
      const lines: string[] = [`WorkBuddy provider: ${models.length} 个模型可用`, `回环代理: ${shim.baseUrl()}`]
      if (catalogProblem) lines.push(`上次拉目录失败: ${catalogProblem}`)
      try {
        const credential = await store.current()
        if (!credential) {
          lines.push('登录状态: 未登录 —— 请打开 WorkBuddy 桌面 App 登录一次')
        } else {
          const expires = credential.expiresAtMs > 0 ? new Date(credential.expiresAtMs).toLocaleString('zh-CN') : '未知'
          lines.push(`登录状态: 已登录${credential.nickname ? ` (${credential.nickname})` : ''}`, `token 过期: ${expires}`)
          const credits = await fetchCredits(credential)
          if (credits) {
            lines.push(`剩余额度: ${credits.totalRemain}`)
            for (const account of credits.accounts) lines.push(`  - ${account.name}: ${account.remains}`)
          }
        }
      } catch (error) {
        lines.push(`状态读取失败: ${error instanceof Error ? error.message : String(error)}`)
      }
      lines.push(`登录文件: ${store.desktopAuthPath()}`, `凭据副本: ${store.ownAuthPath()}`)
      ctx.ui.notify(lines.join('\n'), 'info')
    },
  })

}
