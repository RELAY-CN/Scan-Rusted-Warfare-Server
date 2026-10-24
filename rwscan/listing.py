"""合并每个主服务器的每种查询，保留来源及无法解析的行。"""

import hashlib
import http.client
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit

from .transport import DeadlineStream, TLSStream, authority, open_connection


MAX_HTTP_BYTES = 16 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


class _HTTPAdapter:
    def __init__(self, stream):
        self.stream = stream

    def makefile(self, mode):
        import io

        class Raw(io.RawIOBase):
            def readable(self):
                return True

            def readinto(inner, buffer):
                data = self.stream.recv(len(buffer))
                buffer[:len(data)] = data
                return len(data)

        return io.BufferedReader(Raw())


def request_text(url: str, params: dict, proxy: str, timeout: float, *, post=False, tls_context=None) -> str:
    deadline = time.monotonic() + timeout
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("无效主服务器 URL")
    stream = open_connection(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), proxy, timeout, tls_context=tls_context)
    stream = DeadlineStream(stream, deadline)
    try:
        if parsed.scheme == "https":
            stream = TLSStream(stream, parsed.hostname, tls_context)
        encoded = urlencode(params).encode()
        query = parsed.query
        if not post:
            query += ("&" if query else "") + encoded.decode()
        target = urlunsplit(("", "", parsed.path or "/", query, ""))
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        header = (f"{'POST' if post else 'GET'} {target} HTTP/1.1\r\n"
                  f"Host: {authority(parsed.hostname, port)}\r\n"
                  "User-Agent: rw android 176 zh\r\nLanguage: zh\r\nConnection: close\r\n")
        if post:
            header += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(encoded)}\r\n"
        stream.sendall(header.encode("ascii") + b"\r\n" + (encoded if post else b""))
        response = http.client.HTTPResponse(_HTTPAdapter(stream))
        try:
            response.begin()
            if response.status != 200:
                raise OSError(f"主服务器 HTTP 状态 {response.status}")
            data = response.read(MAX_HTTP_BYTES + 1)
            if len(data) > MAX_HTTP_BYTES:
                raise ValueError("主服务器响应过大")
            return data.decode("utf-8-sig")
        finally:
            response.close()
    finally:
        stream.close()


@dataclass
class Room:
    room_id: str
    host: str
    port: int
    creator: str
    map_name: str
    version: str
    version_code: int
    status: str
    players: int | None
    max_players: int | None
    password_required: bool
    port_open: bool
    dedicated: bool
    private_ip: str = ""
    title: str = ""
    map_type: str = ""
    mods: str = ""
    lookup_code: int = 0
    extra_flag: bool = False
    sources: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    raw_columns: list[str] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    listed_host: str = ""
    listed_port: int | None = None
    lookup_status: str = "pending"
    lookup_error: str | None = None

    def __post_init__(self):
        # 旧结果文件没有解析状态，按待查询处理；列表入口仅用于追溯。
        if not self.listed_host:
            self.listed_host = self.host
        if self.listed_port is None:
            self.listed_port = self.port

    @property
    def address_ready(self):
        return not self.host.startswith("url:") and (self.dedicated or self.lookup_status == "resolved")

    @property
    def name(self):
        return self.creator or self.title

    @property
    def key(self):
        return (self.room_id, self.listed_host, self.listed_port)

    def to_dict(self):
        return {**asdict(self), "room_name": self.name, "is_link": self.host.startswith("url:")}

    @classmethod
    def from_dict(cls, data):
        from dataclasses import fields
        return cls(**{f.name: data[f.name] for f in fields(cls) if f.name in data})


def _flag(value):
    if value.lower() not in ("true", "false"):
        raise ValueError(f"非法布尔字段 {value!r}")
    return value.lower() == "true"


def parse_listing(text: str, source: dict):
    lines = text.splitlines()
    if not lines or not lines[0].startswith("CORRODINGGAMES") or "[FAILED]" in lines[0]:
        raise ValueError("无效列表头：" + (lines[0][:100] if lines else "空响应"))
    rooms, errors = [], []
    for number, line in enumerate(lines[1:], 2):
        if not line.strip():
            continue
        # 原生协议按逗号分隔，不使用 CSV 引号或转义规则。
        columns = line.split(",")
        try:
            if len(columns) < 22:
                raise ValueError(f"需要至少 22 列，收到 {len(columns)} 列")
            port = int(columns[5])
            if not 1 <= port <= 65535:
                raise ValueError("端口不在 1..65535")
            room = Room(
                room_id=columns[18].strip() or columns[0], host=columns[3], port=port,
                creator=columns[7], map_name=columns[9], version=columns[12],
                # 官方Relay允许人数为空，明确记为未知而不丢掉整个房间。
                version_code=int(columns[2]), status=columns[11], players=int(columns[15]) if columns[15] else None,
                max_players=int(columns[16]) if columns[16] else None, password_required=_flag(columns[8]),
                port_open=_flag(columns[6]), dedicated=_flag(columns[17]),
                private_ip=columns[4], title=columns[1], map_type=columns[10],
                mods=columns[20], lookup_code=int(columns[21] or 0), extra_flag=_flag(columns[19]),
                sources=[source.copy()], raw_columns=columns,
            )
            rooms.append(room)
        except ValueError as error:
            errors.append({"line": number, "error": str(error), "raw": line, "source": source})
    return rooms, errors


def merge_rooms(existing: dict, rooms: list[Room]):
    for room in rooms:
        old = existing.get(room.key)
        if old:
            observation = {k: v for k, v in room.to_dict().items() if k not in ("sources", "observations", "resolved_ips", "raw_columns")}
            if observation not in old.observations:
                old.observations.append(observation)
            room.observations = old.observations
            room.sources = old.sources + [x for x in room.sources if x not in old.sources]
            # 任一响应标为官方的同一记录，都不会因抓取顺序被重新纳入扫描。
            room.dedicated = old.dedicated or room.dedicated
        existing[room.key] = room


def fetch_rooms(config, raw_dir: Path | None = None, fetcher=request_text):
    merged, queries, parse_errors = {}, [], []
    pending = [(master, version, beta if version is not None else None)
               for master in config.masters for version in config.list_versions
               for beta in (config.list_betas if version is not None else [None])]
    seen = set()
    for round_number in range(config.discovery_rounds + 1):
        batch = list(dict.fromkeys(x for x in pending if x not in seen))
        if not batch:
            break
        seen.update(batch)

        def fetch(query):
            master, version, beta = query
            source = {"master": master, "game_version": version, "beta": beta}
            params = {"action": "list"}
            if version is not None:
                params.update(game_version=version, game_version_beta=str(beta).lower())
            try:
                body = fetcher(master, params, config.list_proxy, config.request_timeout)
                if raw_dir is not None:
                    raw_dir.mkdir(parents=True, exist_ok=True)
                    name = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()[:16] + ".txt"
                    (raw_dir / name).write_text(body, encoding="utf-8", newline="\n")
                # 先保留原始响应，错误列表头也需要能追溯。
                rooms, errors = parse_listing(body, source)
                return rooms, errors, {**source, "count": len(rooms), "room_ids": sorted({r.room_id for r in rooms}), "error": None, "fetched_at": now()}
            except (OSError, EOFError, ValueError, http.client.HTTPException) as error:
                return [], [], {**source, "count": 0, "room_ids": [], "error": str(error), "fetched_at": now()}

        with ThreadPoolExecutor(max_workers=min(8, len(batch))) as pool:
            for rooms, errors, report in pool.map(fetch, batch):
                merge_rooms(merged, rooms)
                parse_errors.extend(errors)
                queries.append(report)
        if not config.discover_versions or round_number == config.discovery_rounds:
            break
        versions = sorted({r.version_code for r in merged.values() if r.version_code >= 0})
        pending = [(m, v, b) for m in config.masters for v in versions for b in config.list_betas]
    # 列表瞬时变化也能引起差异，报告只描述本次采样，不推断服务端的过滤实现。
    differences = []
    for query in queries:
        baseline = next((q for q in queries if q["master"] == query["master"] and q["game_version"] is None and not q["error"]), None)
        if query["game_version"] is not None and not query["error"] and baseline:
            a, b = set(baseline["room_ids"]), set(query["room_ids"])
            differences.append({"master": query["master"], "game_version": query["game_version"], "beta": query["beta"],
                                "only_versioned": sorted(b - a), "only_unversioned": sorted(a - b)})
    return list(merged.values()), {"queries": queries, "differences": differences, "parse_errors": parse_errors}


def exclusion_reason(room: Room, config):
    if room.host.startswith("url:"):
        return "link"
    if config.exclude_dedicated and room.dedicated:
        return "dedicated"
    if room.room_id in config.exclude_room_ids:
        return "room_id"
    if room.address_ready and (room.host in config.exclude_ips or set(room.resolved_ips) & set(config.exclude_ips)):
        return "ip"
    return None


def resolve_hosts(rooms: list[Room]):
    errors = []
    for host in sorted({r.host for r in rooms if r.address_ready}):
        try:
            try:
                ips = [str(ipaddress.ip_address(host))]
            except ValueError:
                ips = sorted({result[4][0] for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
            for room in rooms:
                if room.address_ready and room.host == host:
                    room.resolved_ips = ips
        except OSError as error:
            errors.append({"host": host, "error": str(error)})
    return errors


def aggregate(rooms: list[Room]):
    result = {}
    for room in rooms:
        # get 未成功时，公共入口不能作为真实服务器参与聚合。
        if not room.address_ready:
            continue
        for ip in room.resolved_ips or [room.host]:
            ports = result.setdefault(ip, {})
            ports.setdefault(str(room.port), []).append(room.to_dict())
    return {ip: {p: ports[p] for p in sorted(ports, key=int)} for ip, ports in sorted(result.items())}


def lookup_challenge(code: int) -> str:
    if code == 0:
        return ""
    prefix, length, seed = "", 0, None
    if 0 < code < 100000:
        prefix, length = "x", 10
    elif code < 200000 and code > 0:
        prefix, length = "y", 11
    elif code < 300000 and code > 0:
        prefix, length = "z", 12
    elif code < 1000000 and code > 0:
        prefix, length, seed = "xx", 13, code - 300000
    elif code < 2000000 and code > 0:
        prefix, length, seed = "yy", 14, code - 1000000
    else:
        return "NA"
    value = hashlib.md5((prefix + str(code)).encode()).hexdigest()[:length]
    if seed is not None:
        from .protocol import connect_key
        value += "-" + connect_key(seed)
    return value


def lookup_room(config, room_id: str, code: int, password: str | None, *, deadline=None):
    challenge = lookup_challenge(code)
    params = {"action": "get", "game_id": room_id, "c": challenge}
    if password is not None:
        digest = room_id + password
        for _ in range(4):
            digest = hashlib.sha256(digest.encode()).hexdigest().upper()
        params["p_hash"] = digest
    errors = []
    for master in config.masters:
        timeout = config.request_timeout if deadline is None else min(config.request_timeout, deadline - time.monotonic())
        if timeout <= 0:
            raise TimeoutError("主服务器 get 超过房间总时限")
        try:
            lines = request_text(master, params, config.list_proxy, timeout, post=True).splitlines()
            if not lines or not lines[0].startswith("CORRODINGGAMES"):
                raise ValueError("get 返回无效响应头")
            if "[FAILED]" in lines[0]:
                raise ValueError("get 返回失败：" + (lines[1] if len(lines) > 1 else "无错误详情"))
            if len(lines) < 5:
                raise ValueError("get 返回截断响应")
            expected = hashlib.sha256(("game_" + challenge).encode()).hexdigest()[:14]
            if expected.lower() not in lines[2].lower():
                raise ValueError("get 返回校验值不匹配")
            columns = lines[4].split(",")
            if len(columns) <= 18:
                raise ValueError("get 地址行列数不足")
            host, port = columns[3].strip(), int(columns[5])
            if not host or host.startswith("url:") or any(c.isspace() or ord(c) < 32 for c in host):
                raise ValueError("get 返回非法服务器地址")
            if not 1 <= port <= 65535:
                raise ValueError("get 返回端口不在 1..65535")
            return host, port
        except (OSError, EOFError, ValueError, http.client.HTTPException) as error:
            errors.append(f"{master}: {error}")
    raise OSError("所有主服务器 get 失败：" + "; ".join(errors))


def room_password(room, config):
    for key in (room.room_id, authority(room.host, room.port), authority(room.listed_host, room.listed_port)):
        if key in config.passwords:
            return config.passwords[key]
    return None


def resolve_room_address(room, config, *, deadline=None):
    """非官方记录统一通过 get 定址，成功后 host/port 是唯一实际地址。"""
    if room.host.startswith("url:"):
        room.lookup_status = "link"
        return
    if room.dedicated:
        room.lookup_status = "official"
        return
    if room.lookup_status == "resolved":
        return
    if room.lookup_status == "failed":
        # 同一轮列表查询的失败不在扫描阶段重复请求，更不能回退公共入口。
        raise OSError(room.lookup_error or "房间 get 地址解析失败")
    room.resolved_ips = []
    try:
        host, port = lookup_room(config, room.room_id, room.lookup_code, room_password(room, config), deadline=deadline)
    except (OSError, EOFError, ValueError, http.client.HTTPException) as error:
        room.lookup_status, room.lookup_error = "failed", str(error)
        raise
    room.host, room.port = host, port
    room.lookup_status, room.lookup_error = "resolved", None


def resolve_room_addresses(rooms, config):
    def resolve(room):
        try:
            resolve_room_address(room, config)
        except (OSError, EOFError, ValueError, http.client.HTTPException):
            # 具体失败已保存到房间，报告与输出都使用同一状态。
            pass
        return {"room_id": room.room_id, "listed_host": room.listed_host, "listed_port": room.listed_port,
                "host": room.host if room.address_ready else None, "port": room.port if room.address_ready else None,
                "status": room.lookup_status, "error": room.lookup_error}

    with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
        return list(pool.map(resolve, rooms))
