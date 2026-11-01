# 铁锈战争房间与关键词扫描器

获取公开房间列表，加入房间监听公告和聊天，并记录关键词命中及服务器地址。
需要 Python 3.10+，仅使用标准库。默认客户端网络版本为 1.15 的 `176`。

## 使用

复制 `config.example.json` 为 `config.json`，设置 `keywords` 后运行：

```bash
python -m rwscan list --config config.json
python -m rwscan scan --config config.json
```

也可以使用 `python scan.py`。复用已保存的列表、限制扫描数量或指定房间：

```bash
python -m rwscan scan --config config.json --rooms-file output/rooms.json --limit 1
python -m rwscan scan --config config.json --rooms-file output/rooms.json --room-id u_具体房间ID
python -m rwscan list --config config.json --version 176 --version 151
```

关键词按包含关系匹配，默认不区分大小写。扫描器不会主动发送聊天。
`listen_seconds` 是每个房间整条跳转链的网络 I/O 时间预算，包含代理握手和地址查询；调大可延长监听。DNS 解析和磁盘写入不受 socket 超时限制。

## 房间列表

- 查询 gs1/gs4 的无版本列表、`list_versions` 中各版本的正式和 Beta 列表，再查询新发现的版本，最多 `discovery_rounds` 轮。
- 按房间 ID、公网地址和端口合并，保留查询来源、观测变化和原始字段。同 IP、同端口的不同房间不会合并。
- 非官方房间先通过 POST `action=get` 获取实际连接地址，包括 `lookup_code=0` 的记录。`host`/`port` 保存解析结果，`listed_host`/`listed_port` 保留列表入口。
- 默认排除列表中 `dedicated=true` 的官方或专用记录，以及 `url:` 网页链接。可用 `--include-dedicated`、`exclude_ips` 和 `exclude_room_ids` 调整；同 IP 的其他房间不会随之被排除。
- 状态、版本、密码和端口开放标记不作为过滤条件。Relay 人数为空时保存为 `null`，终端显示 `?`。

地址查询失败时保留房间和错误，不将列表入口计入 IP 聚合或 CSV。`--rooms-file` 复用已解析地址；旧文件会先查询地址，已标记查询失败的文件需要重新运行 `list`。

主服务器没有全量分页接口，列表只包含查询时可见的公开房间。查询、解析或连接失败会记录错误。

## 代理

`proxies` 轮流分配给房间，同一房间的跳转链沿用同一个代理。`list_proxy` 单独控制列表和地址查询。

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

HTTP 使用 CONNECT；HTTPS 先建立到代理的 TLS 连接并校验证书，再执行 CONNECT。支持 HTTP Basic、SOCKS4a 代理侧域名解析、SOCKS5 无认证或用户名密码认证，以及 IPv6。凭据中的特殊字符需要 URL 百分号编码。代理失败时直接记录错误。

## 密码与 Relay 输入

`passwords` 按房间 ID 或 `host:port` 配置密码。注册和地址查询分别使用游戏协议要求的 SHA-256 摘要和 `p_hash`。

```json
{
  "passwords": {"u_房间ID": "房间密码", "203.0.113.4:5123": "另一密码"},
  "relay_inputs": {"u_房间ID:5": "指定输入", "5": "通用输入"}
}
```

`relay_inputs` 用于回答包 117 的输入提示，包 118 回显对话 ID。未配置答案时记录 `pending_dialog` 并继续监听。

## 输出

| 文件 | 内容 |
| --- | --- |
| `rooms.json` | 候选房间、IP → 端口 → 房间聚合、排除原因 |
| `rooms.csv` | 每 IP、端口、房间一行，含名称、地图、版本、人数和状态 |
| `all_rooms.json` | 全部房间记录，含官方房间和网页链接 |
| `fetch_report.json` | 查询计数、采样差异、地址解析状态及错误 |
| `raw/*.txt` | 主服务器原始响应 |
| `sessions.json` | 各房间连接状态、端点、错误、聊天计数和命中 |
| `matches.jsonl` | 逐条命中消息，含关键词、房间、发送者和端点 |
| `matched_servers.json` | 命中服务器归并结果，含跳转前后端点和地图 |
| `redirects.jsonl` | 每次跳转及候选地址，无论是否命中 |
| `chat.jsonl` | `save_all_chat=true` 时保存的全部聊天 |

命中后立即写入。包 178 跳转会补齐此前命中的端点；共享端点的会话会归并，并从 `sessions.json` 继续累计。连接失败的跳转地址仍会记录为 `connected=false`。每个房间保留列表地图和服务端下发地图。

`action=get` 只是加入前的地址解析：实际地址作为初始端点，列表入口留在房间元数据中，不参与服务器归并，也不设置 `redirected`。历史会话不会被新的列表结果重写。

## 运行限制

默认并发 4，每秒开始一次加入。TCP 接通后，需要收到服务信息或队伍列表才能确认加入。满房、密码、MOD、已开局或自定义校验可能导致加入失败。

退出码：`0` 正常，`1` 参数或配置错误、全部获取失败，`2` 部分查询或扫描失败，`130` 用户中断。

非 1.15 房间会保留，但修改版本数字不能实现完整的其他版本协议。扫描器不执行单位、地图或帧同步模拟，只能匹配连接期间实际收到的消息，无法获取历史聊天或未广播给此玩家的私聊。

## 测试

```bash
python -m unittest discover -s tests -v
python -m rwscan --help
```

测试使用本地模拟服务器，覆盖列表解析、代理隧道、注册、心跳、聊天、跳转和持久化。TLS 测试需要 OpenSSL，未安装时会跳过。
