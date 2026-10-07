/**
 * 回环（loopback）OpenAI 兼容代理 —— 整个方案的关键件。
 *
 * 为什么需要它：Pi 只会讲 OpenAI 那套协议，而 WorkBuddy 上游除了协议之外
 * 还要求一堆自家请求头，并且 token 必须在请求那一刻才解出来（可能刚续过期）。
 * 于是本地起一个只对 127.0.0.1 监听的小服务：
 *
 *   Pi ──(OpenAI /chat/completions, Bearer <一次性密钥>)──> 回环代理
 *                                                          │ 换成 X-User-Id / X-IDE-* + 真 token
 *                                                          ▼
 *                                                   copilot.tencent.com/v2/chat/completions
 *
 * 共享密钥只在同一个进程里存在，从不落盘，也从不发到上游。
 * DSH 版插件叫它 shim，这里沿用同一思路。
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { WorkBuddyCredential } from './credential.ts'
import { chat } from './upstream.ts'

/** 一次请求体上限：带图也要放得下。 */
const MAX_BODY_BYTES = 64 * 1024 * 1024

export interface Shim {
  /** OpenAI 兼容基地址，例如 http://127.0.0.1:53421/v1 */
  baseUrl(): string
  /** 访问校验用的一次性密钥。 */
  token(): string
  port(): number
  close(): Promise<void>
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    request.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        reject(new Error('请求体过大'))
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    request.on('error', reject)
  })
}

function json(response: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload)
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  })
  response.end(body)
}

/** 起一个回环代理。 */
export async function startShim(
  shimToken: string,
  models: () => { id: string }[],
  resolveCredential: () => Promise<WorkBuddyCredential>,
): Promise<Shim> {
  const server: Server = createServer((request, response) => {
    void handle(request, response)
  })

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? '/', `http://${request.headers.host ?? '127.0.0.1'}`)
    const authorized = request.headers.authorization === `Bearer ${shimToken}`

    if (request.method === 'GET' && url.pathname === '/v1/models') {
      if (!authorized) return json(response, 401, { error: { message: 'unauthorized' } })
      return json(response, 200, {
        object: 'list',
        data: models().map(({ id }) => ({ id, object: 'model', owned_by: 'workbuddy' })),
      })
    }

    if (request.method === 'POST' && url.pathname === '/v1/chat/completions') {
      if (!authorized) return json(response, 401, { error: { message: 'unauthorized' } })
      let raw: string
      try {
        raw = await readBody(request)
      } catch (error) {
        return json(response, 400, { error: { message: String(error) } })
      }
      const controller = new AbortController()
      let aborted = false
      request.on('close', () => {
        if (!response.writableEnded) {
          aborted = true
          controller.abort()
        }
      })
      let credential: WorkBuddyCredential
      try {
        credential = await resolveCredential()
      } catch (error) {
        return json(response, 503, {
          error: { message: error instanceof Error ? error.message : String(error), type: 'workbuddy_auth_error' },
        })
      }
      const result = await chat(credential, raw, controller.signal)
      if (aborted) return
      if (!result.ok) {
        const status = result.status === 401 || result.status === 403 ? 401
          : result.status === 429 ? 429
            : result.status === 0 ? 502
              : result.status >= 500 ? 502
                : 400
        return json(response, status, {
          error: { message: result.message, type: 'workbuddy_upstream_error', upstream_status: result.status },
        })
      }
      const upstream = result.response
      response.writeHead(200, {
        'Content-Type': upstream.headers.get('content-type') ?? 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        ...(upstream.headers.get('x-request-id') === null
          ? {}
          : { 'x-request-id': upstream.headers.get('x-request-id') as string }),
      })
      if (!upstream.body) {
        response.end()
        return
      }
      // 直接把上游的 SSE 字节流翻给 Pi，不做重新组包，避免丢精准位。
      const reader = upstream.body.getReader()
      try {
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          if (response.writableEnded) break
          response.write(value)
        }
      } catch {
        // 客户端断开 / 连接被掐断，直接收尾
      }
      response.end()
      return
    }

    json(response, 404, { error: { message: `no route for ${request.method ?? 'GET'} ${url.pathname}` } })
  }

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    // 端口交给内核挑，避免与其他服务撞车。
    server.listen(0, '127.0.0.1', resolve)
  })
  // 关键：unref 之后这个监听句柄不再拖住事件循环，
  // Pi 即使在只加载扩展而不开会话的场景（如 --list-models）也能正常退出。
  server.unref()

  const address = server.address()
  const port = typeof address === 'object' && address !== null ? address.port : 0

  return {
    baseUrl: () => `http://127.0.0.1:${port}/v1`,
    token: () => shimToken,
    port: () => port,
    close: async () => {
      await new Promise<void>(resolve => {
        server.close(() => resolve())
      })
    },
  }
}
