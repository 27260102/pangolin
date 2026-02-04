# Pangolin — Feishu Bot Bridge for CLI Coding Agents

Pangolin 将 CLI 编程代理封装为 Go 服务，并接入飞书事件回调，实现“飞书消息 → CLI 代理 → 飞书回复”的远程编程体验。
当前已支持 Claude Code CLI（stream-json），后续可扩展到 Codex 等工具。
支持菜单事件审批（不污染聊天记录）和自动放行策略。

## 运行前提

- 已安装 Claude Code CLI（`claude` 命令可用）
- Go 1.22
- 飞书开放平台应用已创建
- 若使用 HTTP 回调模式，需要公网域名或内网穿透；WebSocket 模式无需公网回调

## 构建与运行

```bash
export GOCACHE=/tmp/go-build
go mod tidy
go build -o pangolin
./pangolin
```

如需使用环境文件，可复制示例：

```bash
cp .env.example .env
```

## 环境变量

### Claude CLI 认证（必需）

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1/api
export ANTHROPIC_AUTH_TOKEN=cr_xxx
```

### 飞书应用配置（必需）

```bash
export FEISHU_APP_ID=cli_xxx
export FEISHU_APP_SECRET=xxx
export FEISHU_VERIFICATION_TOKEN=xxx
export FEISHU_API_BASE=https://open.feishu.cn/open-apis
```

### 事件接入模式（推荐 WebSocket）

默认使用 SDK 的 WebSocket 长连接，不需要暴露公网回调地址：

```bash
# ws: SDK WebSocket（默认）
# http: 传统回调 URL
# both: 同时开启
export FEISHU_EVENT_MODE=ws
```

### 机器人菜单事件（推荐）

使用“推送事件”的菜单来审批（不污染聊天记录），请配置机器人自定义菜单并将事件 key 写入环境变量：

```bash
export FEISHU_MENU_ACCEPT_KEY=menu_accept_key
export FEISHU_MENU_ACCEPT_ALL_KEY=menu_accept_all_key
export FEISHU_MENU_REJECT_KEY=menu_reject_key
export FEISHU_MENU_PROJECTS_KEY=menu_projects_key
```

事件类型应为：`application.bot.menu_v6`
注意：当前不再支持通过“文字回复”进行审批，必须使用菜单事件。

### 飞书回复模式与分片（可选）

默认只在 Claude 完成后合并发送一条消息。如需流式输出或调节阈值，可设置：

```bash
# merge: 完成后一次性回复（默认）
# stream: 边生成边回复（按阈值节流）
export FEISHU_STREAM_MODE=merge

# 仅在 stream 模式下生效
export FEISHU_STREAM_MIN_CHARS=120
export FEISHU_STREAM_INTERVAL=1.2

# 单条消息最大字节数（UTF-8），默认 150KB
export FEISHU_TEXT_MAX_BYTES=153600
```

### 自动放行工具（可选）

默认会对一些只读/低风险工具“自动放行”（不弹审批），减少切换次数：

```bash
export AUTO_ALLOW_TOOLS="Read;Search;List;Glob;Bash(ls:*);Bash(pwd);Bash(cat:*);Bash(head:*);Bash(tail:*);Bash(wc:*);Bash(stat:*);Bash(git:status,git:diff)"
```

如需调整，请修改 `AUTO_ALLOW_TOOLS` 环境变量。

说明：
- 自动放行只影响“审批”，不限制 Claude 可用工具。
- Bash 子命令支持规则匹配（如 `Bash(ls:*)`、`Bash(git:status)`）。

### 飞书加密策略（可选）

如果飞书回调开启了“加密策略”，需要设置：

```bash
export FEISHU_ENCRYPT_KEY=xxx
```

注意：当前代码只做了签名校验，未做事件解密。如开启加密策略，需要补解密逻辑或先关闭加密。

### 项目管理（SQLite）

```bash
export PROJECT_DB_PATH=./projects.db
```

项目按用户隔离，目录在同一用户下唯一。

## 开源准备

- 许可证：MIT（见 `LICENSE`）
- 建议发布到 GitHub 后将 `go.mod` 的 module 改成你的仓库路径（如 `github.com/you/pangolin`）

## 飞书平台配置

### 事件订阅

若使用 HTTP 回调模式（`FEISHU_EVENT_MODE=http` 或 `both`）：

- 回调 URL: `https://你的域名/feishu/events`
- 订阅事件：`im.message.receive_v1`
- 订阅事件（菜单审批）：`application.bot.menu_v6`
- 校验方式：Verification Token（与 `FEISHU_VERIFICATION_TOKEN` 一致）

若使用 WebSocket 模式（默认）：

- 在飞书应用后台启用事件订阅的长连接/Socket 方式
- 勾选 `im.message.receive_v1`、`application.bot.menu_v6` 等事件
- 无需填写公网回调 URL

### 卡片回调

若使用 HTTP 回调模式，项目管理卡片需要配置回调地址：

- 回调 URL: `https://你的域名/feishu/callback`
- 回调类型：卡片交互（action trigger）

WebSocket 模式无需配置卡片回调地址。

### 需要的权限（最小集合）

- 发送消息（必需）
  - `im:message:send_as_bot`
- 接收消息（根据场景）
  - 私聊：`im:message.p2p_msg:readonly`
  - 群聊 @：`im:message.group_at_msg:readonly`

权限开通后，确保机器人已加入群聊或可被用户私聊。

默认启动：
- API: `http://localhost:6000`
- Docs: `http://localhost:6000/docs`

## 快速自测

1) 启动服务  
2) 飞书里私聊机器人发送消息  
3) 服务器日志应看到 `im.message.receive_v1` 和 Claude 的输出  
4) 飞书收到机器人回复

## 指令

- `/model`：展示模型选择卡片，点击切换模型（会重启线程但保留 session_id）
- `/compact`：生成摘要并创建“压缩会话”，切换到新线程（上下文被摘要替代）

说明：`/model` 的候选列表来自本机 Claude CLI 的历史记录（`~/.claude/projects/*.jsonl`）。

## 未来规划

- 已完成：切换到 SDK WebSocket 模式（不再暴露公网接口），实现本地/内网直连。
- 接入 Codex 等更多 CLI 代理，实现多引擎可切换的运行后端。
- 多节点部署与调度，支持横向扩展与任务分发。
- 永久记忆：恢复项目时可一键“回忆”，自动将历史对话浓缩为摘要并注入工具上下文，帮助快速续接此前工作。

## 常见问题

- 回复内容是 `Invalid API key · Please run /login`
  - Claude CLI 未认证，检查 `ANTHROPIC_*` 环境变量

- 飞书不回复
  - 检查 `im:message:send_as_bot` 权限是否开通
  - 确认机器人已加入会话/群聊
  - 确认菜单事件 `application.bot.menu_v6` 已订阅（如需菜单审批）

- 事件能收到但解析不到文本
  - 可能开启了加密策略，需要解密事件体或关闭加密
