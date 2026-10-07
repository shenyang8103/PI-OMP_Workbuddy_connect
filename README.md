# pi-workbuddy-connect

把 WorkBuddy 桌面 App 里含的模型接进 [Pi](https://pi.dev) 和 [oh-my-pi (omp)](https://github.com/can1357/oh-my-pi)：装好就用，`/model` 里直接能选，**不用申请任何 API Key**。

> 一份代码、两个宿主：同一个插件包同时兼容 Pi 与 omp —— Pi 读 `package.json` 里的 `pi` 字段、omp 读 `omp` 字段，核心逻辑零分叉。

本项目是对 DSH 插件 [dsh-workbuddy-connect](https://github.com/corrinehu/dsh-workbuddy-connect) 的一次逆向研究与移植 —— 先弄明白它在 DSH 上是怎么工作的，再把同一套机制搬到 Pi 上。

> 仅用于个人学习研究，使用时请遵守 WorkBuddy 的服务条款。

---

## 一、DSH 版插件是怎么工作的

读完源码后，它的链路只有四步，全部在本地完成：

```
┌──────────────┐   ① 读登录文件      ┌────────────────────────────────────────┐
│  WorkBuddy   │ ──────────────────> │ CodeBuddyExtension/Data/Public/auth/   │
│  桌面 App    │                     │   workbuddy-desktop.info（加密）       │
└──────────────┘                     └───────────────┬────────────────────────┘
                                                     │ ② 请 App 自己的 Electron 吐出密钥
                                                     ▼
                                        sha256(atRestSecretKey) → AES-256-GCM
                                                     │ ③ 拿到 accessToken
                 ┌───────────────────────────────────┴──────────┐
                 ▼                                              │
   GET /v3/config（装成官方 CLI 的 UA）                          │
     → 拿 cli 名单里的模型目录                                    │
                                                                ▼
   POST /v2/chat/completions ←── ④ 回环 shim 转发 ─── Pi / DSH 发出的
                                  带上自家的 X-* 身份头       OpenAI 请求
```

**关键点：**

1. **凭据来源**：桌面 App 的登录文件。macOS 在 `~/Library/Application Support/`，Windows 在 `%LOCALAPPDATA%`（旧版 `%APPDATA%`），Linux 在 XDG 目录。

2. **为什么要拉起 Electron**：WorkBuddy 5.6 之后，文件里的 `accessToken`/`refreshToken` 不再是明文，而是 `$wbEncrypted` 信封（AES-256-GCM）。密钥由 App 自身的 at-rest 保护机制持有，外部拿不到，**只能让 App 自己说出来**：

   ```bash
   ELECTRON_RUN_AS_NODE=1 "WorkBuddy.exe" -e 'process.stdout.write(String(process._linkedBinding("electron_browser_workbuddy_storage").loggerGet()))'
   ```

   输出 `{version:1, atRestSecretKey:"<base64 32B>"}`。`key = sha256(secret)`，`keyId = sha256(key)` 的前 16 位十六进制 —— 必须和信封里的 `keyId` 对上才允许解密（这也是"换了一台机器/一个安装就解不开"的原因）。

3. **为什么要有回环代理（shim）**：Pi/DSH 只会讲 OpenAI 协议，而上游还要这些：

   | 差异 | 处理 |
   |---|---|
   | `X-User-Id` / `X-Enterprise-Id` / `X-Domain` / `X-IDE-*` 等身份头 | shim 按当前凭据现场拼 |
   | token 要按需续期 | shim 在请求时才解出最新 token |
   | 上游拒绝 `developer` 角色（报 11128 渠道非法） | 改写成 `system` |
   | 上游拒绝对象形式的 `tool_choice` | 拍平成字符串，`none` 时连 tools 一起删 |
   | 上游只接受流式 | 强制 `stream: true` |

   于是本地起一个只监听 `127.0.0.1` 的一次性服务：Pi 照 OpenAI 的样子发给它（Bearer 一次性密钥），它换成上游方言转发回去，SSE 字节流原样透传。

4. **模型目录**：`GET https://copilot.tencent.com/v3/config`，**UA 必须是官方 CLI 形态**（`CLI/2.63.2 CodeBuddy/2.63.2`）——网关按 UA 分流，App 形态的 UA 拿到的是另一份名单。取 `agents` 里名为 `cli` 的那份名单，和可用行求交集。

---

## 二、实现（同时兼容 Pi 与 oh-my-pi）

```
pi-workbuddy-connect/
├─ index.ts            扩展入口：注册 provider + /workbuddy 命令
├─ src/credential.ts   登录文件定位、信封解密、按需续期
├─ src/upstream.ts     /v3/config 目录、/v2/chat/completions 转发、续期、额度
├─ src/shim.ts         127.0.0.1 一次性 OpenAI 兼容代理
└─ package.json        Pi 与 omp 双扩展清单（pi / omp 两个 key 同指 ./index.ts）
```

注册形式为 Pi/omp 共用的 legacy `ProviderConfig`，`api: "openai-completions"`，`baseUrl` 指向 shim —— 流式、工具调用、usage、取消这些全部交给宿主内置实现，这里只做协议与身份转换。Pi 与 omp 的扩展 API 同源（`registerProvider` / `registerCommand` / `openai-completions`），所以同一份代码两个宿主都能直接加载。

**为了不绑定任一宿主，做了 2 处最小化改动（核心逻辑 `src/*` 未动）：**

1. `index.ts` 去掉对宿主包的 `import type`（如 `@earendil-works/pi-coding-agent`），改为本地声明一个只用到的 `interface ExtensionAPI` —— 这样既不依赖 Pi 的包名，也不依赖 omp 的包名（`@oh-my-pi/pi-coding-agent`）。
2. `package.json` 同时写 `pi.extensions` 与 `omp.extensions`，各自只认自己的 key，指向同一个 `./index.ts`。

> Pi 基于 Node 加载 `.ts`；omp 基于 Bun，对 `constructor(readonly ...)` 这类参数属性语法也原生支持。本插件只用 `node:crypto` / `fs` / `path` / `os` / `http` 几个内建模块，两种运行时都兼容。

一个细节：监听句柄会 `unref()`。因为宿主在 `--list-models` 这类"只加载扩展、不开会话"的场景也会执行 factory，Unref 之后这个服务既不占用端口太久，也不会把进程拖住。

## 三、安装

### 装到 Pi

```bash
# 方式 A：放进用户扩展目录（本机已采用）
mkdir -p ~/.pi/agent/extensions
cp -r . ~/.pi/agent/extensions/pi-workbuddy-connect

# 方式 B：临时加载，不写入配置
pi --extension ./index.ts ...
```

改动后在同一会话里用 `/reload` 重新加载即可。

### 装到 oh-my-pi (omp)

```bash
# 本地目录（会软链到源目录，保留单份代码；推荐）
omp install ./pi-workbuddy-connect

# 或指向 git 仓库
# omp install github:你的用户名/pi-workbuddy-connect
```

安装后 `omp plugin list` 应能看到 `● pi-workbuddy-connect@0.1.0`。

前置条件：装了并登录过 **WorkBuddy 桌面 App**。
运行时要求：Pi 需要 Node ≥ 22.19；omp 自带 Bun，无需额外 Node。

## 四、使用

Pi 与 omp 用法一致，只是把命令从 `pi` 换成 `omp`：

```bash
# Pi
pi                                   # 然后 Ctrl+L 或 /model 选 WorkBuddy 下的模型
pi --provider workbuddy --model glm-5.3-flash
pi --provider workbuddy --model hy4-preview -p "写个快排"
/workbuddy                           # 会话里查看连接状态、token 过期时间、剩余额度

# oh-my-pi（命令换成 omp，其余相同）
omp --provider workbuddy --model glm-5.3-flash
```

实测通过：
- 本机 WorkBuddy 5.x + Pi 1.0.4：17 个模型可选，普通对话、工具调用（bash/read/edit）、推理档位都正常。
- 本机 WorkBuddy 5.x + oh-my-pi：扩展由 omp 加载无误，同样注册 17 个模型，`/model` 可选。

## 五、配置

| 环境变量 | 用途 |
|---|---|
| `WORKBUDDY_AUTH_FILE` | 直接指定登录文件路径 |
| `WORKBUDDY_ELECTRON_BIN` | 直接指定 WorkBuddy 的 exe / Electron 路径（自动找不到时用） |
| `WORKBUDDY_DEBUG=1` | 往 stderr 打 tracing 日志 |

运行时文件都在 `~/.pi/agent/workbuddy-connect/`：`catalog.json`（目录快照，离线兜底）、`auth.json`（续期后的凭据副本，权限 600）。

## 六、边界与安全

- **绝不修改桌面 App 的登录文件**，续期结果只写自己的副本；为了少打扰上游，只在 token 临近过期时才刷新（提前量 5 分钟）。
- 回环服务的密钥是每个进程随机生成的，只在内存里，既不落盘也不发往上游；上游只收到 WorkBuddy 自己的 token。
- 只监听 `127.0.0.1`，外网访问不到。
- 解密钥需要拉起 WorkBuddy 的 exe —— 找不到时用 `WORKBUDDY_ELECTRON_BIN` 指一下。
- 依赖桌面端未公开接口，WorkBuddy 更新后可能需要跟着调整；`credential.ts` 里的 `keyId` 校验会第一时间告诉你"密钥对不上"。
- 全部请求都在本地发出，本插件不向任何第三方上传数据。
