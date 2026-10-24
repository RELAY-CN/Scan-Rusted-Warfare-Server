"""1.15 协议字段与 Java DataInput/DataOutput 兼容编码。"""

import hashlib
import re
import struct
import time

from .transport import recv_exact


MAGIC = "com.corrodinggames.rts"
PREREGISTER = 160
SERVER_PREREGISTER = 161
REGISTER = 110
CHAT = 141
RECONNECT = 178
# 原版 APIEncryption.i/j 初值，独立于161预注册响应中的挑战字段。
INITIAL_CHALLENGE_FIRST = 55
INITIAL_CHALLENGE_SECOND = 66


class ProtocolError(ValueError):
    pass


def int32(value):
    return (value + 2147483648) % 4294967296 - 2147483648


class Writer:
    def __init__(self):
        self.data = bytearray()

    def int(self, value):
        self.data.extend(struct.pack(">i", int32(value)))
        return self

    def byte(self, value):
        self.data.append(value & 255)
        return self

    def boolean(self, value):
        return self.byte(int(value))

    def float(self, value):
        self.data.extend(struct.pack(">f", value))
        return self

    def utf(self, text):
        # Java modified UTF 对 NUL 与 UTF-16 surrogate 单独编码。
        utf16 = text.encode("utf-16-be", "surrogatepass")
        result = bytearray()
        for index in range(0, len(utf16), 2):
            unit = int.from_bytes(utf16[index:index + 2], "big")
            if 1 <= unit <= 127:
                result.append(unit)
            elif unit <= 2047:
                result.extend((0xC0 | unit >> 6, 0x80 | unit & 63))
            else:
                result.extend((0xE0 | unit >> 12, 0x80 | (unit >> 6) & 63, 0x80 | unit & 63))
        if len(result) > 65535:
            raise ProtocolError("Java UTF 字符串超过 65535 字节")
        self.data.extend(len(result).to_bytes(2, "big") + result)
        return self

    def optional_utf(self, text):
        self.boolean(text is not None)
        if text is not None:
            self.utf(text)
        return self


class Reader:
    def __init__(self, data):
        self.data = memoryview(data)
        self.position = 0

    def take(self, count):
        if count < 0 or self.position + count > len(self.data):
            raise ProtocolError("协议包字段截断")
        value = self.data[self.position:self.position + count].tobytes()
        self.position += count
        return value

    def int(self):
        return struct.unpack(">i", self.take(4))[0]

    def byte(self):
        return self.take(1)[0]

    def boolean(self):
        return bool(self.byte())

    def utf(self):
        encoded = self.take(int.from_bytes(self.take(2), "big"))
        utf16 = bytearray()
        index = 0
        while index < len(encoded):
            first = encoded[index]
            if first <= 127:
                unit, size = first, 1
            elif 0xC0 <= first <= 0xDF:
                size = 2
                if index + size > len(encoded) or encoded[index + 1] & 0xC0 != 0x80:
                    raise ProtocolError("无效 modified UTF 双字节")
                unit = (first & 31) << 6 | encoded[index + 1] & 63
            elif 0xE0 <= first <= 0xEF:
                size = 3
                if index + size > len(encoded) or any(x & 0xC0 != 0x80 for x in encoded[index + 1:index + 3]):
                    raise ProtocolError("无效 modified UTF 三字节")
                unit = (first & 15) << 12 | (encoded[index + 1] & 63) << 6 | encoded[index + 2] & 63
            else:
                raise ProtocolError("无效 modified UTF 首字节")
            utf16.extend(unit.to_bytes(2, "big"))
            index += size
        return utf16.decode("utf-16-be", "surrogatepass")

    def optional_utf(self):
        return self.utf() if self.boolean() else None


def send_packet(stream, packet_type, payload):
    data = payload.data if isinstance(payload, Writer) else payload
    stream.sendall(struct.pack(">ii", len(data), packet_type) + data)


def receive_packet(stream, max_bytes):
    size, packet_type = struct.unpack(">ii", recv_exact(stream, 8))
    if not 0 <= size <= max_bytes:
        raise ProtocolError(f"非法数据包长度 {size}")
    return packet_type, recv_exact(stream, size)


def connect_key(seed):
    values = [44000 * seed, seed, 13000 * seed, 28000 + seed, 75000 * seed,
              160000 + seed, 850000 * seed, 1800000 * seed, 3800000 * seed]
    value = f"c:{seed}m:{int32(seed * 87 + 24)}"
    value += "".join(f"{i}:{int32(number)}" for i, number in enumerate(values))
    floating = 4000.0 * 11.0 * seed
    # 原版 connectKey 种子为 1..1,000,000；Java 在 >= 1e7 时使用科学记数法。
    if abs(floating) >= 10000000:
        mantissa, exponent = format(floating, ".15e").split("e")
        mantissa = mantissa.rstrip("0").rstrip(".")
        if "." not in mantissa:
            mantissa += ".0"
        text = mantissa + "E" + str(int(exponent))
    else:
        text = str(floating)
    return value + f"t1:{text}d:{int32(seed * 5)}"


def preregister(config, query=None):
    return (Writer().utf(MAGIC).int(4).int(config.network_version).int(config.platform)
            .optional_utf(query).utf(config.name).utf(config.locale).utf(""))


def decode_preregister(data):
    r = Reader(data)
    magic, layout = r.utf(), r.int()
    if not 0 <= layout <= 2:
        raise ProtocolError(f"未知预注册响应版本 {layout}")
    network, game, package, server_id = r.int(), r.int(), r.utf(), r.utf()
    key = r.int() if layout >= 1 else 0
    first, second = (r.int(), r.int()) if layout >= 2 else (0, 0)
    return {"magic": magic, "network_version": network, "game_version": game, "package": package,
            "server_id": server_id, "key": key, "challenge_a": first, "challenge_b": second}


def register(config, client_id, server_id, key, challenge, password=None):
    password_hash = hashlib.sha256(password.encode()).hexdigest().upper() if password is not None else None
    client_hash = hashlib.sha256((client_id + server_id).encode()).hexdigest().upper()
    return (Writer().utf(MAGIC).int(5).int(config.network_version).int(config.game_version).utf(config.name)
            .optional_utf(password_hash).utf(config.package_name).utf(client_hash).int(config.unit_checksum)
            .utf(connect_key(key)).utf(f"#{challenge & 0xFFFFFF:06X}"))


def decode_chat(data):
    r = Reader(data)
    message, layout, sender, index = r.utf(), r.byte(), r.optional_utf(), r.int()
    site = r.int() if 3 <= layout < 128 else -1
    return {"message": message, "sender": sender, "connection_index": index, "site": site}


def decode_redirect(data):
    r = Reader(data)
    marker, reason, relay, count = r.byte(), r.int(), r.boolean(), r.int()
    if not 0 <= count <= 32:
        raise ProtocolError(f"跳转候选地址数量越界：{count}")
    return {"marker": marker, "reason": reason, "use_relay": relay, "addresses": [r.utf() for _ in range(count)]}


def parse_address(address):
    text = address.strip().replace("\\", "/")
    if text.startswith("get|"):
        raise ProtocolError("get 地址必须先通过主服务器解析")
    if text.startswith("[TCP]"):
        text = text[5:]
    if not any(c in text for c in ":./") and len(text) > 4 and text != "localhost":
        text = f"{text[0]}.relay.corrodinggames.com/{text}"
    hostpart, separator, query = text.partition("/")
    query = query.strip() or None if separator else None
    if hostpart.lower().endswith(".relay"):
        hostpart += ".corrodinggames.com"
    if hostpart.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", hostpart)
        if not match:
            raise ProtocolError("无效 IPv6 地址")
        host, port = match[1], int(match[2] or 5123)
    elif ":" in hostpart:
        host, port_text = hostpart.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError as error:
            raise ProtocolError("无效跳转端口") from error
    else:
        host, port = hostpart, 5123
    if not host or not 1 <= port <= 65535 or any(c in text for c in "\r\n\x00") or "://" in text:
        raise ProtocolError("无效连接地址")
    return host, port, query


def challenge_reply(data, first, second, config):
    started = time.monotonic()
    r = Reader(data)
    request_id, kind = r.int(), r.int()
    if r.boolean():
        first = r.int()
    if r.boolean():
        second = r.int()
    if kind == 0:
        result = str(first)
    elif kind == 1:
        result = str(second)
    elif kind == 2:
        result = connect_key(first)
    elif kind in (3, 4):
        result = hashlib.sha256(f"{first}|{second}".encode()).hexdigest().upper()[:14]
    elif kind in (5, 6):
        target, prefix, limit = r.utf(), r.utf(), r.int()
        if limit < 0 or limit > config.max_challenge_iterations:
            raise ProtocolError(f"挑战迭代数 {limit} 超出配置上限")
        if kind == 6:
            prefix += str(first)
        result = "-1"
        for i in range(limit + 1):
            if time.monotonic() - started > config.challenge_timeout:
                raise ProtocolError("挑战计算超时")
            if hashlib.sha256((prefix + str(i)).encode()).hexdigest().upper()[:14] == target:
                result = str(i)
                break
    elif kind == 7:
        text, repeat = r.utf(), r.int()
        if not 0 <= repeat <= 10000 or len(text.encode("utf-16-be", "surrogatepass")) * repeat > 120000:
            raise ProtocolError("字符串挑战超过限制")
        result = text * repeat
    else:
        raise ProtocolError(f"未知挑战类型 {kind}")
    return Writer().int(request_id).int(kind).utf(result).float((time.monotonic() - started) * 1000), first, second
