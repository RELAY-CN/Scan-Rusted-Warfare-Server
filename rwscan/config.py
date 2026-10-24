"""配置以 JSON 为单一事实源，未知字段和无效参数直接报错。"""

import json
import math
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from urllib.parse import urlsplit


@dataclass
class Config:
    masters: list[str] = field(default_factory=lambda: [
        "http://gs1.corrodinggames.com/masterserver/1.4/interface",
        "http://gs4.corrodinggames.net/masterserver/1.4/interface",
    ])
    list_versions: list[int | None] = field(default_factory=lambda: [None, 176, 151, 173])
    list_betas: list[bool] = field(default_factory=lambda: [False, True])
    discover_versions: bool = True
    discovery_rounds: int = 2
    exclude_dedicated: bool = True
    exclude_ips: list[str] = field(default_factory=list)
    exclude_room_ids: list[str] = field(default_factory=list)
    proxies: list[str] = field(default_factory=lambda: ["direct"])
    list_proxy: str = "direct"
    keywords: list[str] = field(default_factory=list)
    case_sensitive: bool = False
    name: str = "RoomScanner"
    network_version: int = 176
    game_version: int = 176
    unit_checksum: int = 678359601
    package_name: str = "com.corrodinggames.rts"
    platform: int = 1
    locale: str = "zh"
    passwords: dict[str, str] = field(default_factory=dict)
    relay_inputs: dict[str, str] = field(default_factory=dict)
    connect_timeout: float = 8.0
    request_timeout: float = 15.0
    listen_seconds: float = 20.0
    concurrency: int = 4
    join_interval: float = 1.0
    max_redirects: int = 5
    max_packet_bytes: int = 8 * 1024 * 1024
    max_challenge_iterations: int = 100000
    challenge_timeout: float = 2.0
    output_dir: str = "output"
    save_all_chat: bool = False

    def validate(self):
        for key in ("masters", "proxies", "keywords", "exclude_ips", "exclude_room_ids"):
            value = getattr(self, key)
            if not isinstance(value, list) or any(not isinstance(x, str) or not x.strip() for x in value):
                raise ValueError(f"{key} 必须是非空字符串组成的数组")
        if not self.masters or not self.proxies:
            raise ValueError("masters/proxies 不能为空")
        for url in self.masters:
            parsed = urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username:
                raise ValueError("masters 只接受 HTTP/HTTPS URL")
        if not isinstance(self.list_versions, list) or not self.list_versions or any(
            x is not None and (type(x) is not int or not 0 <= x <= 2147483647) for x in self.list_versions
        ):
            raise ValueError("list_versions 必须包含非负整数或 null")
        if not isinstance(self.list_betas, list) or not self.list_betas or any(type(x) is not bool for x in self.list_betas):
            raise ValueError("list_betas 必须包含布尔值")
        for key in ("discover_versions", "exclude_dedicated", "case_sensitive", "save_all_chat"):
            if type(getattr(self, key)) is not bool:
                raise ValueError(f"{key} 必须是布尔值")
        for key in ("discovery_rounds", "concurrency", "max_packet_bytes", "max_challenge_iterations"):
            if type(getattr(self, key)) is not int or getattr(self, key) < 1:
                raise ValueError(f"{key} 必须是正整数")
        if type(self.max_redirects) is not int or self.max_redirects < 0:
            raise ValueError("max_redirects 必须是非负整数")
        for key in ("network_version", "game_version", "unit_checksum"):
            if type(getattr(self, key)) is not int or not -2147483648 <= getattr(self, key) <= 2147483647:
                raise ValueError(f"{key} 超出 Java int 范围")
        if self.platform not in (1, 2, 3) or type(self.platform) is not int:
            raise ValueError("platform 必须是 1、2 或 3")
        for key in ("connect_timeout", "request_timeout", "listen_seconds", "challenge_timeout", "join_interval"):
            value = getattr(self, key)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0 or (key != "join_interval" and value == 0):
                raise ValueError(f"{key} 必须是有效正数，join_interval 可为 0")
        if not isinstance(self.name, str) or not 2 <= len(self.name.encode("utf-16-be")) // 2 <= 20 or re.search(r"[\x00-\x1f]", self.name):
            raise ValueError("name 必须是 2 到 20 个 Java 字符且无控制字符")
        for key in ("locale", "package_name", "output_dir", "list_proxy"):
            if not isinstance(getattr(self, key), str) or not getattr(self, key).strip():
                raise ValueError(f"{key} 必须是非空字符串")
        for key in ("passwords", "relay_inputs"):
            values = getattr(self, key)
            if not isinstance(values, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in values.items()):
                raise ValueError(f"{key} 必须是字符串到字符串的对象")
        from .transport import parse_proxy
        for proxy in self.proxies + [self.list_proxy]:
            parse_proxy(proxy)
        return self


def load_config(path: str | None) -> Config:
    data = {} if path is None else json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("配置根节点必须是对象")
    unknown = set(data) - {f.name for f in fields(Config)}
    if unknown:
        raise ValueError("未知配置字段：" + ", ".join(sorted(unknown)))
    return Config(**data).validate()
