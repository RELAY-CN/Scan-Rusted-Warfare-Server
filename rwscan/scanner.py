"""只监听聊天，不发送聊天或游戏命令；每条连接都受到有限时长约束。"""

import ipaddress
import socket
import struct
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from .listing import exclusion_reason, lookup_room, resolve_room_address, room_password
from .protocol import (CHAT, RECONNECT, SERVER_PREREGISTER, INITIAL_CHALLENGE_FIRST,
                       INITIAL_CHALLENGE_SECOND, ProtocolError, Reader, Writer,
                       challenge_reply, decode_chat, decode_preregister, decode_redirect, parse_address,
                       preregister, receive_packet, register, send_packet)
from .storage import Store
from .transport import DeadlineStream, authority, open_connection


def describe_endpoint(host, port, query=None, *, role="origin"):
    try:
        ips = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            ips = sorted({x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
        except OSError:
            # SOCKS4a/SOCKS5 支持代理侧 DNS；此处未知 IP 显式保留域名。
            ips = []
    return {"host": host, "port": port, "query": query, "ips": ips, "role": role,
            "connected": False, "ip_source": "literal" if ips == [host] else "dns_candidates"}


class RateLimiter:
    def __init__(self, interval):
        self.interval, self.next_at = interval, 0.0
        self.lock = threading.Lock()

    def wait(self, deadline):
        with self.lock:
            scheduled = max(self.next_at, time.monotonic())
            if scheduled >= deadline:
                raise TimeoutError("加入速率限制超过房间总时限")
            self.next_at = scheduled + self.interval
        # 只在锁内预留时刻，避免其他会话等待锁时耗尽各自的预算。
        delay = scheduled - time.monotonic()
        if delay > 0:
            time.sleep(delay)


def _resolve_address(address, config, password, deadline):
    if address.startswith("get|"):
        parts = address.split("|")
        if len(parts) != 5:
            raise ProtocolError("get 跳转地址必须有五个字段")
        host, port = lookup_room(config, parts[1], int(parts[2]), password, deadline=deadline)
        return host, port, None
    return parse_address(address)


def scan_room(room, config, store, proxy_index=0, limiter=None):
    session_id = store.begin(room, proxy_index)
    proxy = config.proxies[proxy_index]
    client_id = str(uuid.uuid4())
    deadline = time.monotonic() + config.listen_seconds
    candidates = []
    visited = set()
    redirects = 0
    status = "lookup_failed"
    normalized = [(word, word if config.case_sensitive else word.casefold()) for word in config.keywords]
    try:
        resolve_room_address(room, config, deadline=deadline)
        # get 是加入前的定址，不构成 TCP 跳转；公共列表入口不进入端点图。
        origin = describe_endpoint(room.host, room.port)
        room.resolved_ips = origin["ips"]
        reason = exclusion_reason(room, config)
        if reason:
            store.metadata(session_id, "exclusion_reason", reason)
            status = "excluded"
        else:
            candidates = [(room.host, room.port, None, "origin")]
            store.endpoint(session_id, origin)
            status = "connection_failed"
        password = room_password(room, config)
        while candidates and time.monotonic() < deadline:
            stream, endpoint = None, None
            for host, port, query, role in candidates:
                identity = (host, port, query)
                if identity in visited:
                    store.error(session_id, "跳转循环：" + authority(host, port))
                    status = "redirect_loop"
                    continue
                visited.add(identity)
                endpoint = describe_endpoint(host, port, query, role=role)
                store.endpoint(session_id, endpoint)
                try:
                    if limiter:
                        limiter.wait(deadline)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    stream = open_connection(host, port, proxy, min(config.connect_timeout, remaining))
                    endpoint["connected"] = True
                    if proxy in ("direct", "direct://"):
                        endpoint["ips"] = [stream.getpeername()[0]]
                        endpoint["ip_source"] = "tcp_peer"
                    store.endpoint(session_id, endpoint)
                    break
                except (OSError, EOFError, ValueError) as error:
                    store.error(session_id, f"{authority(host, port)} 连接失败：{error}")
                    stream = None
            if stream is None:
                break
            stream = DeadlineStream(stream, deadline)
            next_candidates = []
            try:
                send_packet(stream, 160, preregister(config, endpoint.get("query")))
                first, second = INITIAL_CHALLENGE_FIRST, INITIAL_CHALLENGE_SECOND
                registered = False
                status = "no_server_info"
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        if status == "listening":
                            status = "listened"
                        break
                    # recv_exact 在一次读包里持续读取，超时即终止，避免半包被当作新头。
                    stream.settimeout(remaining)
                    packet_type, payload = receive_packet(stream, config.max_packet_bytes)
                    if packet_type == SERVER_PREREGISTER:
                        info = decode_preregister(payload)
                        store.metadata(session_id, "server_info", info)
                        send_packet(stream, 110, register(config, client_id, info["server_id"], info["key"], info["challenge_a"], password))
                        registered = True
                        status = "registered_unconfirmed"
                    elif packet_type == 108:
                        r = Reader(payload)
                        stamp = r.take(8)
                        r.byte()
                        send_packet(stream, 109, stamp + b"\x01\x3c")
                    elif packet_type == CHAT:
                        chat = decode_chat(payload)
                        text = chat["message"] if config.case_sensitive else chat["message"].casefold()
                        words = [word for word, needle in normalized if needle in text]
                        store.chat(session_id, endpoint.copy(), chat, words)
                    elif packet_type == 106:
                        r = Reader(payload)
                        r.utf(); r.int(); r.int()
                        store.metadata(session_id, "observed_map", r.utf())
                        if registered:
                            status = "listening"
                    elif packet_type == 115:
                        # 队伍列表也是加入成功的可观察证据，保留 payload 的游戏部分无需加载。
                        if registered:
                            status = "listening"
                    elif packet_type == 151:
                        reply, first, second = challenge_reply(payload, first, second, config)
                        send_packet(stream, 152, reply)
                    elif packet_type == RECONNECT:
                        redirect = decode_redirect(payload)
                        store.redirect(session_id, {"kind": "packet_178", "from": endpoint.copy(), **redirect})
                        for address in redirect["addresses"]:
                            try:
                                host, port, query = _resolve_address(address, config, password, deadline)
                                advertised = describe_endpoint(host, port, query, role="redirect")
                                store.endpoint(session_id, advertised)
                                next_candidates.append((host, port, query, "redirect"))
                            except (OSError, EOFError, ValueError) as error:
                                store.error(session_id, f"跳转地址 {address!r} 解析失败：{error}")
                        if redirects >= config.max_redirects:
                            raise ProtocolError("超过 max_redirects 跳转上限")
                        redirects += 1
                        status = "redirected" if next_candidates else "redirect_failed"
                        break
                    elif packet_type == 117:
                        r = Reader(payload)
                        r.byte()
                        dialog_id, message = r.int(), r.utf()
                        text = message if config.case_sensitive else message.casefold()
                        store.chat(session_id, endpoint.copy(), {"message": message, "sender": None,
                                   "kind": "relay_dialog", "dialog_id": dialog_id},
                                   [word for word, needle in normalized if needle in text])
                        answer = config.relay_inputs.get(f"{room.room_id}:{dialog_id}",
                                 config.relay_inputs.get(str(dialog_id)))
                        if answer is not None:
                            send_packet(stream, 118, Writer().byte(1).int(dialog_id).utf(answer))
                        else:
                            store.metadata(session_id, "pending_dialog", {"dialog_id": dialog_id, "message": message})
                    elif packet_type in (111, 150):
                        reason = Reader(payload).utf()
                        store.error(session_id, ("踢出：" if packet_type == 150 else "断开：") + reason)
                        # TCP 接通不等于加入成功；服务器拒绝注册必须显式失败。
                        status = "kicked" if packet_type == 150 else ("disconnected" if status == "listening" else "join_rejected")
                        break
                    elif packet_type == 113:
                        status = "password_required"
                        store.error(session_id, "房间要求密码或密码不正确")
                        break
                    elif packet_type == 120:
                        # 扫描器不执行对局模拟，但继续接收系统/玩家聊天与心跳。
                        send_packet(stream, 112, Writer().boolean(True).boolean(False))
            except socket.timeout:
                status = "listened" if status == "listening" else status
            except EOFError as error:
                store.error(session_id, str(error))
                status = "connection_closed" if status == "listening" else status
            except (OSError, ValueError) as error:
                store.error(session_id, str(error))
                status = "protocol_error"
            finally:
                try:
                    send_packet(stream, 111, Writer().utf("Scanner finished"))
                except OSError:
                    pass
                stream.close()
            candidates = next_candidates
    except (OSError, EOFError, ValueError) as error:
        store.error(session_id, str(error))
    finally:
        store.metadata(session_id, "room", room.to_dict())
        store.finish(session_id, status)
    return store.sessions[session_id]


def scan_rooms(rooms, config, on_result=None):
    store = Store(config.output_dir, config.save_all_chat)
    limiter = RateLimiter(config.join_interval)
    results = []
    with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
        jobs = [pool.submit(scan_room, room, config, store, i % len(config.proxies), limiter) for i, room in enumerate(rooms)]
        for future in as_completed(jobs):
            result = future.result()
            results.append(result)
            if on_result:
                on_result(result)
    return results
