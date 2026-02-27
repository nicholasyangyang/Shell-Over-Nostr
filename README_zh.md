# Shell Over Nostr

[English](README.md)

通过 Nostr NIP-04 加密私信在远程机器上执行 Shell 命令。

本工具利用去中心化的 Nostr 网络实现安全的远程命令执行，采用端到端加密保护您的命令和输出内容，防止中继服务器操作者和第三方窥探。

## 功能特性

- **去中心化通信**：使用 Nostr 中继服务器而非中心化服务器
- **端到端加密**：所有消息使用 NIP-04 协议加密（AES-256-CBC）
- **密码认证**：可选的 HMAC-SHA256 密码保护
- **访问控制**：可限制特定 Nostr 公钥的访问权限
- **会话持久化**：Shell 模式下保持工作目录状态
- **多中继支持**：连接多个中继服务器以提高可靠性
- **代理支持**：通过环境变量支持 HTTPS/SOCKS 代理

## 系统要求

- Python 3.10+
- 依赖包：`aiohttp`、`secp256k1`、`cryptography`

```bash
pip install aiohttp secp256k1 cryptography
```

## 架构图

```
┌─────────────┐                    ┌─────────────┐
│   CLIENT    │                    │   SERVER    │
│ (your PC)   │                    │ (remote PC) │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  NIP-04 Encrypted DM (kind: 4)   │
       │  ┌────────────────────────────┐  │
       └──┤    ┌──────────────────┐    ├──┘
          │    │   NOSTR RELAYS   │    │
          │    │  (relay.damus.io)│    │
          │    │  (nos.lol)       │    │
          │    │  (relay.primal)  │    │
          │    └──────────────────┘    │
          └────────────────────────────┘
```

## 使用方法

### 服务端模式

在您想要控制的远程机器上运行：

```bash
python main.py server [nsec] [选项]
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `nsec` | 可选 | 服务端私钥（nsec1... 格式或 64 位十六进制）。如未提供，将自动生成新密钥并保存到 `.nostr_key` 文件 |
| `--allow <npub>` | 可选 | 仅允许指定的 Nostr 公钥连接 |
| `--password <密码>` | 可选 | 用于认证的共享密码。客户端必须提供相同的密码 |

**示例：**

```bash
# 使用自动生成的密钥启动服务端
python main.py server

# 使用指定的私钥启动服务端
python main.py server nsec1...

# 启动带密码保护的服务端
python main.py server --password 我的密码123

# 启动服务端并限制特定客户端访问
python main.py server --allow npub1abc123... --password 我的密码123
```

### 客户端模式 - 单命令执行 (exec)

在远程服务端执行单条命令：

```bash
python main.py exec <服务端npub> "命令" [nsec] [选项]
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `<服务端npub>` | 是 | 服务端的公钥（npub1... 格式） |
| `"命令"` | 是 | 要执行的 Shell 命令（需要用引号包围！） |
| `nsec` | 可选 | 客户端私钥。如未提供，将使用已保存的密钥或自动生成新密钥 |
| `--verbose on\|off` | 可选 | 显示调试日志（默认：`on`） |
| `--password <密码>` | 可选 | 认证密码（必须与服务端密码一致） |

**示例：**

```bash
# 执行简单命令
python main.py exec npub1server123... "ls -la"

# 使用密码认证执行命令
python main.py exec npub1server123... "df -h" --password 我的密码123

# 关闭详细输出执行命令
python main.py exec npub1server123... "cat /etc/os-release" --verbose off --password 我的密码123

# 使用指定客户端密钥执行命令
python main.py exec npub1server123... "uptime" nsec1client...
```

### 客户端模式 - 交互式 Shell (shell)

启动交互式 Shell 会话：

```bash
python main.py shell <服务端npub> [nsec] [选项]
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `<服务端npub>` | 是 | 服务端的公钥（npub1... 格式） |
| `nsec` | 可选 | 客户端私钥。如未提供，将使用已保存的密钥或自动生成新密钥 |
| `--verbose on\|off` | 可选 | 显示调试日志（默认：`on`） |
| `--password <密码>` | 可选 | 认证密码（必须与服务端密码一致） |

**示例：**

```bash
# 启动交互式 Shell
python main.py shell npub1server123...

# 使用密码启动 Shell
python main.py shell npub1server123... --password 我的密码123

# 关闭详细输出启动 Shell
python main.py shell npub1server123... --verbose off --password 我的密码123
```

## 密钥管理

### 密钥工作机制

1. **首次运行（未提供密钥）**：自动生成新的密钥对，并保存到脚本同目录下的 `.nostr_key` 文件中。

2. **提供密钥参数**：如果您提供了 `nsec`（私钥），它将被保存到 `.nostr_key` 文件，并在后续运行中使用。

3. **后续运行**：如果 `.nostr_key` 文件存在，将自动使用其中保存的密钥。

### 密钥文件格式

`.nostr_key` 文件包含 JSON 格式数据：

```json
{
  "nsec": "nsec1...",
  "npub": "npub1..."
}
```

### 重要安全提示

- **备份您的密钥！** 如果丢失私钥（nsec），您将失去您的身份标识。
- **保密 nsec！** 永远不要分享您的私钥。
- **只分享 npub！** 您的公钥（npub）可以安全分享——这是他人识别您的方式。

## 身份认证

### 密码认证

当服务端设置了 `--password` 时：

1. 客户端计算：`HMAC-SHA256(密码, sid + nonce)`
2. 认证令牌包含在 NIP-04 加密载荷中
3. 服务端在执行命令前验证令牌
4. 密码错误 = 静默拒绝（不给攻击者任何错误提示）

**优势：**
- 令牌端到端加密（中继服务器操作者无法看到）
- 每个会话使用唯一的 `sid` 和 `nonce`（防止重放攻击）
- 即使有人知道您的 npub，没有密码也无法连接

### 访问白名单

当服务端设置了 `--allow <npub>` 时：

- 只有指定的 npub 可以执行命令
- 所有其他连接尝试都会被静默拒绝
- 建议与 `--password` 结合使用以获得最大安全性

## 可配置参数

以下常量可在源代码中修改：

| 常量 | 默认值 | 说明 |
|------|--------|------|
| `EXEC_TIMEOUT` | 30 | 单条命令最大执行时间（秒） |
| `RECV_TIMEOUT` | 60 | 等待服务端响应的最大时间（秒） |
| `COALESCE_MS` | 30 | 输出合并延迟（毫秒） |
| `MAX_FRAME_BYTES` | 12288 | 每个输出帧的最大字节数 |

### 中继服务器列表

默认中继服务器（可在源代码中修改 `RELAYS` 列表）：

```python
RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.oxtr.dev",
    "wss://relay.primal.net",
    "wss://nostr-pub.wellorder.net",
]
```

### 代理配置

设置环境变量以使用代理：

```bash
export HTTPS_PROXY="http://127.0.0.1:7890"
# 或
export https_proxy="socks5://127.0.0.1:1080"
# 或
export ALL_PROXY="http://proxy.example.com:8080"
```

## 协议详情

### 帧格式（NIP-04 加密 JSON）

**客户端 -> 服务端（执行请求）：**
```json
{
  "t": "exec",
  "sid": "<会话ID>",
  "nonce": "<随机数>",
  "cmd": "<Shell命令>",
  "auth": "<HMAC令牌>"
}
```

**服务端 -> 客户端（输出数据块）：**
```json
{
  "t": "out",
  "sid": "<会话ID>",
  "nonce": "<随机数>",
  "seq": <序列号>,
  "d": "<Base64输出>"
}
```

**服务端 -> 客户端（命令完成）：**
```json
{
  "t": "done",
  "sid": "<会话ID>",
  "nonce": "<随机数>",
  "rc": <返回码>,
  "cwd": "<当前目录>"
}
```

**服务端 -> 客户端（错误）：**
```json
{
  "t": "err",
  "sid": "<会话ID>",
  "nonce": "<随机数>",
  "msg": "<错误信息>"
}
```

### 安全特性

1. **端到端加密**：所有通信使用 NIP-04 协议（AES-256-CBC + ECDH 密钥派生）
2. **Schnorr 签名**：事件使用 Schnorr 签名确保真实性
3. **重放保护**：每条命令使用唯一的 `sid` + `nonce` 防止重放攻击
4. **有序输出**：序列号确保输出数据块按正确顺序到达
5. **去重处理**：服务端跟踪已处理的事件 ID，防止重复执行

## 快速入门指南

### 第一步：安装依赖

```bash
pip install aiohttp secp256k1 cryptography
```

### 第二步：启动服务端（在远程机器上）

```bash
python main.py server --password 我的密码
```

记录输出中显示的 `npub` —— 客户端需要使用它。

### 第三步：执行命令（在本地机器上）

```bash
# 单条命令
python main.py exec npub1... "ls -la" --password 我的密码

# 交互式 Shell
python main.py shell npub1... --password 我的密码
```

## 故障排除

### "no relay connected"（无法连接中继）

- 检查您的网络连接
- 如果在防火墙后，尝试设置代理
- 部分中继可能暂时不可用——请稍后重试

### 命令超时

- 命令执行时间可能超过了 `EXEC_TIMEOUT`（默认 30 秒）
- 检查命令是否需要用户输入

### "rejected (wrong password)"（密码错误被拒绝）

- 确保客户端和服务端的密码完全一致
- 密码区分大小写

### "rejected npub ... (not in allow list)"（公钥不在白名单中）

- 客户端的 npub 不在服务端的允许列表中
- 在服务端使用 `--allow` 选项指定正确的客户端 npub

## 许可证

[MIT](LICENSE)
