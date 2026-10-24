# 铁锈战争房间与关键词扫描器

Python 3.10+，运行只使用标准库，无需 pip 安装。默认使用 1.15 网络版本 176。

## 使用

复制 `config.example.json` 为 `config.json`，修改 `keywords` 后运行：

```bash
python -m rwscan list --config config.json
python -m rwscan scan --config config.json
```

也可以用 `python scan.py`。先列出房间，再对指定记录试跑：

```bash
python -m rwscan scan --config config.json --rooms-file output/rooms.json --limit 1
python -m rwscan scan --config config.json --rooms-file output/rooms.json --room-id u_具体房间ID
python -m rwscan list --config config.json --version 176 --version 151
```

`scan` 获取列表后逐房间加入并接收服务器公告、玩家聊天和 Relay 输入提示，逐条执行包含匹配；默认不区分大小写。扫描器不主动发聊天。列表阶段先执行 `action=get` 定址；`listen_seconds` 是随后每个房间整条扫描跳转链的网络 I/O 总预算，包含代理握手、旧文件待解析地址和跳转地址的 get 请求；调大可延长监听。系统 DNS 解析和磁盘写入耗时不受 socket 超时保证。列表所有状态、版本、密码房间和端口未开放的记录都保留并尝试，失败会记录。

## 列表获取与官方排除

- 分别查询 gs1/gs4 的无 `game_version` 请求，以及 `list_versions` 各版本的正式/Beta 请求；再查询结果中发现的新版本，最多 `discovery_rounds` 轮。
- 合并依据是房间 ID、公网地址和端口；同 IP/端口的不同房间 ID 都保留，保留查询来源、观测变化及原始列。
- 所有非官方服务器先通过 POST `action=get` 获取真实 IP/端口，再做 DNS、IP 排除和聚合；`lookup_code=0` 也查询。`dedicated=true` 的官方/专用记录直接使用列表地址，网页链接不查询。
- `host`/`port` 在 get 成功后保存实际连接地址，`listed_host`/`listed_port` 保留列表入口；`lookup_status` 为 `pending`、`resolved`、`failed`、`official` 或 `link`。get 失败保留记录和 `lookup_error`，不把公共入口纳入 `by_ip`/CSV，退出码为 2。
- `fetch_report.json` 展示每次查询计数、ID 集合、与无版本采样的差异和失败。房间会实时变化，差异不等于已证明服务端按版本过滤。
- 默认按第 17 列 `dedicated=true` 排除主列表标记的官方/专用房间；不把一个官方房间所在 IP 的所有其他房间一起删除。该标记不是可验证的服务器所有权证明，可用 `exclude_ips`/`exclude_room_ids` 补充，或 `--include-dedicated` 调整。
- `url:` 类型的 Discord/网页链接单独归为排除项；`all_rooms.json` 仍保留全部原始房间记录。公网 DNS 无法确定时保留域名并报告。
- Relay 的人数列允许为空；JSON 中保存为 `null`，终端显示 `?`，房间仍保留并按正常规则过滤。
- 没有全量分页接口；无法保证获得未上架、被主服务器隐藏或抓取间隔内消失的房间。某次查询失败不会静默丢弃错误，退出码为 2。

## 代理

`proxies` 轮流分配到每个房间，整个跳转链沿用同一个代理。示例：

```json
{
  "proxies": [
    "direct",
    "http://user:password@127.0.0.1:8080",
    "https://user:password@proxy.example:443",
    "socks4://user@127.0.0.1:1080",
    "socks5://user:password@127.0.0.1:1080"
  ],
  "list_proxy": "direct"
}
```

HTTP 使用 CONNECT；HTTPS 是到代理的 TLS 加 CONNECT，证书校验开启。支持 HTTP Basic、SOCKS4a 代理侧域名解析、SOCKS5 无认证/用户名密码及 IPv6。凭据特殊字符需 URL 百分号编码。隧道失败直接记录，不自动改用直连。`list_proxy` 独立控制列表及 `action=get` 请求，也支持以上五种方式。

## 密码与 Relay 输入

`passwords` 按房间 ID 或 `host:port` 配置密码，注册时发送原版 SHA-256 大写摘要，`action=get` 使用原版 `p_hash`。配置示例：

```json
{
  "passwords": {"u_房间ID": "房间密码", "203.0.113.4:5123": "另一密码"},
  "relay_inputs": {"u_房间ID:5": "指定输入", "5": "通用输入"}
}
```

`relay_inputs` 是包 117 的人工指定输入，包 118 回显对话 ID。未指定时记录 `pending_dialog` 并继续监听，不猜测答案。

## 输出

| 文件 | 内容 |
| --- | --- |
| `rooms.json` | 非官方候选房间、IP → 端口 → 房间聚合及排除原因 |
| `rooms.csv` | 每 IP/端口/房间一行，含房间/玩家名、地图、版本、人数、状态 |
| `all_rooms.json` | 合并后的全部记录，含官方和网页链接 |
| `fetch_report.json` | 各列表查询采样差异、get 解析状态与错误、列表解析错误、DNS 错误 |
| `raw/*.txt` | 各主服务器查询的原始响应 |
| `sessions.json` | 每个房间的连接状态、端点、错误、聊天计数与命中 |
| `matches.jsonl` | 逐条匹配聊天，含匹配词、房间 ID、发送者和端点 |
| `matched_servers.json` | 命中服务器归并结果，包含跳转前后 IP/端口、房间、地图及 `redirected` 标记 |
| `redirects.jsonl` | 单独记录每次跳转及全部候选地址，未命中也记录 |
| `chat.jsonl` | `save_all_chat=true` 时保存收到的全部聊天 |

匹配后立即写入；后续发现跳转会更新同一服务器的所有端点，早于跳转的命中也会补齐。端点共享的扫描会话通过图归并，跨运行读取 `sessions.json` 继续累计。跳转地址即使连接失败也记录，`connected=false`；DNS 候选 IP 的 `ip_source=dns_candidates`，直连实际远端为 `tcp_peer`。每个房间保留列表地图及服务端实际下发地图。

`action=get` 是加入前的地址解析，实际地址作为 origin，公共列表入口只保留在房间元数据，不参与端点归并，也不设置 `redirected`。包 178 的实际跳转仍归并前后端点。`--rooms-file` 复用 `resolved` 状态；旧文件没有解析状态时先 get，并按真实地址应用 IP 排除。get 失败产生 `lookup_failed` 会话且没有占位端点；已标记失败的结果需重新运行 `list` 获取新地址。历史 `sessions.json` 已有的归并记录继续保留，新的列表解析不会重写旧会话。

默认并发 4、全局每秒开始一次加入。退出码：0 正常；1 参数/配置/全部获取失败；2 部分查询或房间扫描失败；130 用户中断。TCP 接通后仍需服务信息或队伍列表确认加入，确认前关闭或拒绝连接会返回 2。非 1.15 房间会保留但默认客户端仍是 176，版本拒绝会记录，不能通过改版本数字实现完整其他版本协议。满房、密码、MOD、已经开局和自定义校验也可能拒绝加入。

这是聊天监听客户端，不执行单位、地图或帧同步模拟。只能匹配连接期间实际收到的消息；历史聊天、未广播给此玩家的私聊、需要游戏模拟后才能到达的内容无法恢复。协议 151 支持类型 0..7，但工作量超限显式失败。
