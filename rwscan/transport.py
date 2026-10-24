"""TCP 代理隧道；HTTPS 指客户端到代理的 TLS CONNECT。"""

import base64
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


class TransportError(OSError):
    pass


@dataclass(frozen=True)
class Proxy:
    scheme: str
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""


def parse_proxy(value: str) -> Proxy:
    if value in ("direct", "direct://"):
        return Proxy("direct")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https", "socks4", "socks5") or not parsed.hostname:
        raise ValueError("代理只支持 direct、http://、https://、socks4://、socks5://")
    port = parsed.port or {"http": 8080, "https": 443, "socks4": 1080, "socks5": 1080}[parsed.scheme]
    if not 1 <= port <= 65535 or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("无效代理地址")
    user, password = unquote(parsed.username or ""), unquote(parsed.password or "")
    if "\x00" in user + password:
        raise ValueError("代理凭据不能包含 NUL")
    return Proxy(parsed.scheme, parsed.hostname, port, user, password)


def recv_exact(stream, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise EOFError(f"连接关闭：需要 {count} 字节，收到 {len(result)} 字节")
        result.extend(chunk)
    return bytes(result)


class DeadlineStream:
    """每次底层 I/O 重算总预算，分片数据不能无限延长会话。"""

    def __init__(self, stream, deadline):
        self.stream, self.deadline = stream, deadline

    def _timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("连接总时限已到")
        self.stream.settimeout(remaining)

    def recv(self, count):
        self._timeout()
        return self.stream.recv(count)

    def sendall(self, data):
        self._timeout()
        self.stream.sendall(data)

    def settimeout(self, value):
        self.stream.settimeout(value)

    def close(self):
        self.stream.close()


class TLSStream:
    """使用 MemoryBIO 保留已有 TLS 隧道，支持 HTTPS 目标经过 HTTPS 代理。"""

    def __init__(self, stream, host: str, context=None):
        self.stream = stream
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = (context or ssl.create_default_context()).wrap_bio(
            self.incoming, self.outgoing, server_side=False, server_hostname=host
        )
        self._operate(self.tls.do_handshake)

    def _flush(self):
        while self.outgoing.pending:
            self.stream.sendall(self.outgoing.read())

    def _operate(self, action):
        while True:
            try:
                result = action()
                self._flush()
                return result
            except ssl.SSLWantWriteError:
                self._flush()
            except ssl.SSLWantReadError:
                self._flush()
                data = self.stream.recv(65536)
                if not data:
                    self.incoming.write_eof()
                else:
                    self.incoming.write(data)

    def recv(self, count):
        try:
            return self._operate(lambda: self.tls.read(count))
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            return b""

    def sendall(self, data):
        view = memoryview(data)
        while view:
            written = self._operate(lambda: self.tls.write(view))
            view = view[written:]

    def settimeout(self, value):
        self.stream.settimeout(value)

    def close(self):
        self.stream.close()


def authority(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def open_connection(host: str, port: int, proxy_url: str, timeout: float, *, tls_context=None):
    if not host or any(c in host for c in "\r\n\x00") or not 1 <= port <= 65535:
        raise ValueError("无效目标地址")
    proxy = parse_proxy(proxy_url)
    deadline = time.monotonic() + timeout
    raw = socket.create_connection((host, port) if proxy.scheme == "direct" else (proxy.host, proxy.port), timeout)
    stream = raw
    try:
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if time.monotonic() >= deadline:
            raise TimeoutError("TCP 建连超过总时限")
        if proxy.scheme == "direct":
            return stream
        # 认证、TLS 和分片读取共用一次建连预算，不能逐次重置 socket 超时。
        stream = DeadlineStream(raw, deadline)
        if proxy.scheme == "https":
            stream = TLSStream(stream, proxy.host, tls_context)
        if proxy.scheme in ("http", "https"):
            target = authority(host.encode("idna").decode(), port)
            request = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
            if proxy.username or proxy.password:
                credentials = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
                request += f"Proxy-Authorization: Basic {credentials}\r\n"
            stream.sendall((request + "\r\n").encode("ascii"))
            header = bytearray()
            # 按字节读取头，避免吃掉紧随其后的游戏数据。
            while not header.endswith(b"\r\n\r\n"):
                if len(header) >= 16384:
                    raise TransportError("代理响应头过大")
                header.extend(recv_exact(stream, 1))
            status = bytes(header).split(b"\r\n", 1)[0].split()
            if len(status) < 2 or status[1] != b"200":
                raise TransportError("代理拒绝 CONNECT，HTTP 状态 " + (status[1].decode("ascii", "replace") if len(status) > 1 else "无效"))
        elif proxy.scheme == "socks4":
            try:
                address = ipaddress.IPv4Address(host).packed
                suffix = b""
            except ipaddress.AddressValueError:
                if ":" in host:
                    raise TransportError("SOCKS4 不支持 IPv6")
                address = b"\x00\x00\x00\x01"
                suffix = host.encode("idna") + b"\x00"
            stream.sendall(b"\x04\x01" + port.to_bytes(2, "big") + address + proxy.username.encode() + b"\x00" + suffix)
            response = recv_exact(stream, 8)
            if response[0] not in (0, 4) or response[1] != 90:
                raise TransportError(f"SOCKS4 连接失败：{response[1]}")
        else:
            methods = b"\x00\x02" if proxy.username or proxy.password else b"\x00"
            stream.sendall(b"\x05" + bytes([len(methods)]) + methods)
            selected = recv_exact(stream, 2)
            if selected[0] != 5 or selected[1] not in methods:
                raise TransportError("SOCKS5 无可用认证方式")
            if selected[1] == 2:
                user, password = proxy.username.encode(), proxy.password.encode()
                if len(user) > 255 or len(password) > 255:
                    raise TransportError("SOCKS5 凭据过长")
                stream.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
                if recv_exact(stream, 2) != b"\x01\x00":
                    raise TransportError("SOCKS5 认证失败")
            try:
                address = ipaddress.ip_address(host)
                packed = bytes([1 if address.version == 4 else 4]) + address.packed
            except ValueError:
                encoded = host.encode("idna")
                if len(encoded) > 255:
                    raise TransportError("SOCKS5 域名过长")
                packed = b"\x03" + bytes([len(encoded)]) + encoded
            stream.sendall(b"\x05\x01\x00" + packed + port.to_bytes(2, "big"))
            response = recv_exact(stream, 4)
            if response[:3] != b"\x05\x00\x00":
                raise TransportError(f"SOCKS5 连接失败：{response[1]}")
            if response[3] == 1:
                recv_exact(stream, 4)
            elif response[3] == 4:
                recv_exact(stream, 16)
            elif response[3] == 3:
                recv_exact(stream, recv_exact(stream, 1)[0])
            else:
                raise TransportError("SOCKS5 返回未知地址类型")
            recv_exact(stream, 2)
        # 隧道建立后由调用方管理监听预算，解除仅用于代理握手的包装。
        if proxy.scheme == "https":
            stream.stream = raw
        else:
            stream = raw
        stream.settimeout(timeout)
        return stream
    except BaseException:
        stream.close()
        raise
