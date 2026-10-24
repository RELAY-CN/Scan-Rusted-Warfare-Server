import json
import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path
from dataclasses import replace

from rwscan.config import Config
from rwscan.listing import parse_listing
from rwscan.protocol import Reader, Writer, connect_key, receive_packet, send_packet
from rwscan.scanner import RateLimiter, describe_endpoint, scan_room
from rwscan.storage import Store
from tests.helpers import OneServer, read_header
from tests.test_listing import row


class ScannerTests(unittest.TestCase):
    def handshake(self, connection, query=None):
        packet_type, payload = receive_packet(connection, 100000)
        self.assertEqual(160, packet_type)
        r = Reader(payload)
        self.assertEqual("com.corrodinggames.rts", r.utf())
        self.assertEqual((4, 176, 1, query), (r.int(), r.int(), r.int(), r.optional_utf()))
        send_packet(connection, 161, Writer().utf("custom relay").int(2).int(176).int(176).utf("server").utf("server-uuid").int(4321).int(9).int(0))
        kind, payload = receive_packet(connection, 100000)
        self.assertEqual(110, kind)
        r = Reader(payload)
        r.utf(); r.int(); r.int(); r.int(); r.utf(); r.optional_utf(); r.utf(); r.utf()
        self.assertEqual(678359601, r.int())
        self.assertEqual(connect_key(4321), r.utf())
        self.assertEqual("#000009", r.utf())
        send_packet(connection, 106, Writer().utf("server").int(176).int(0).utf("真实地图"))

    def test_chat_heartbeat_challenge_redirect_and_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config(output_dir=directory, keywords=["关键词", "hello"], listen_seconds=3, join_interval=0)
            store = Store(directory)
            initial_challenges = []

            def target_handler(connection):
                self.handshake(connection, "target-room")
                send_packet(connection, 108, struct.pack(">qB", 12345, 0))
                kind, payload = receive_packet(connection, 100000)
                self.assertEqual((109, struct.pack(">qBB", 12345, 1, 60)), (kind, payload))
                # APIEncryption 初始种子独立于161注册挑战，未更新时仍需按原版回答。
                for challenge_type in (0, 1):
                    send_packet(connection, 151, Writer().int(7).int(challenge_type).boolean(False).boolean(False))
                    kind, payload = receive_packet(connection, 100000)
                    r = Reader(payload)
                    initial_challenges.append((kind, r.int(), r.int(), r.utf()))
                send_packet(connection, 151, Writer().int(1).int(0).boolean(True).int(987).boolean(False))
                kind, payload = receive_packet(connection, 100000)
                r = Reader(payload)
                self.assertEqual((152, 1, 0, "987"), (kind, r.int(), r.int(), r.utf()))
                send_packet(connection, 141, Writer().utf("HELLO 😀关键词").byte(3).optional_utf("玩家").int(1).int(2))
                send_packet(connection, 111, Writer().utf("done"))
                receive_packet(connection, 100000)

            with socket.socket() as refused, OneServer(target_handler) as target:
                refused.bind(("127.0.0.1", 0))
                refused_port = refused.getsockname()[1]
                def origin_handler(connection):
                    self.handshake(connection)
                    # 命中后才跳转，必须重新聚合并补齐目标端点。
                    send_packet(connection, 141, Writer().utf("跳转前关键词").byte(3).optional_utf(None).int(0).int(-1))
                    send_packet(connection, 178, Writer().byte(0).int(3).boolean(False).int(2)
                                .utf(f"127.0.0.1:{refused_port}").utf(f"[TCP]127.0.0.1:{target.port}/target-room"))
                    receive_packet(connection, 100000)

                with OneServer(origin_handler) as origin:
                    room = parse_listing("CORRODINGGAMES\n" + row("local", "127.0.0.1", origin.port), {})[0][0]
                    result = scan_room(room, config, store)
                    self.assertEqual("disconnected", result["status"])
                    self.assertEqual(2, result["chat_count"])
                    self.assertEqual(2, len(result["matches"]))
                    self.assertEqual([(152, 7, 0, "55"), (152, 7, 1, "66")], initial_challenges)
                    groups = json.loads((Path(directory) / "matched_servers.json").read_text())
                    self.assertEqual(1, len(groups))
                    group = groups[0]
                    self.assertTrue(group["redirected"])
                    self.assertEqual({f"127.0.0.1:{origin.port}", f"127.0.0.1:{refused_port}", f"127.0.0.1:{target.port}"}, set(group["ip_ports"]))
                    self.assertFalse(next(e for e in group["endpoints"] if e["port"] == refused_port)["connected"])
                    self.assertEqual("真实地图", group["rooms"][0]["observed_map"])
                    self.assertTrue((Path(directory) / "redirects.jsonl").exists())
                    self.assertEqual(1, len(Store(directory)._groups()))

    def test_redirect_loop_and_bad_frame_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config(output_dir=directory, listen_seconds=2)

            def handler(connection):
                self.handshake(connection)
                send_packet(connection, 178, Writer().byte(0).int(3).boolean(False).int(1).utf(f"127.0.0.1:{server.port}"))
                receive_packet(connection, 100000)

            with OneServer(handler) as server:
                room = parse_listing("CORRODINGGAMES\n" + row("local", "127.0.0.1", server.port), {})[0][0]
                result = scan_room(room, config, Store(directory))
                self.assertTrue(any("循环" in e["error"] for e in result["errors"]))

            def bad_handler(connection):
                receive_packet(connection, 100000)
                connection.sendall(struct.pack(">ii", -1, 141))
                receive_packet(connection, 100000)

            with OneServer(bad_handler) as server:
                room.port = server.port
                result = scan_room(room, config, Store(directory))
                self.assertEqual("protocol_error", result["status"])
                self.assertTrue(any("长度" in e["error"] for e in result["errors"]))

    def test_password_error_and_no_match(self):
        with tempfile.TemporaryDirectory() as directory:
            def handler(connection):
                self.handshake(connection)
                send_packet(connection, 113, Writer().int(0))
                receive_packet(connection, 100000)

            with OneServer(handler) as server:
                room = parse_listing("CORRODINGGAMES\n" + row("local", "127.0.0.1", server.port), {})[0][0]
                result = scan_room(room, Config(output_dir=directory, listen_seconds=2), Store(directory))
                self.assertEqual("password_required", result["status"])
                self.assertEqual([], json.loads((Path(directory) / "matched_servers.json").read_text()))

    def test_master_lookup_obeys_room_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            def slow_master(connection):
                read_header(connection)
                time.sleep(0.7)

            with OneServer(slow_master) as master:
                config = Config(output_dir=directory, listen_seconds=0.1, request_timeout=2,
                                masters=[f"http://127.0.0.1:{master.port}/interface"])
                room = parse_listing("CORRODINGGAMES\n" + row(), {})[0][0]
                room.lookup_code = 37
                started = time.monotonic()
                result = scan_room(room, config, Store(directory))
                self.assertLess(time.monotonic() - started, 0.5)
                self.assertEqual("lookup_failed", result["status"])
                self.assertTrue(result["errors"])

    def test_later_run_merges_shared_endpoint_into_earlier_match(self):
        with tempfile.TemporaryDirectory() as directory:
            room = parse_listing("CORRODINGGAMES\n" + row(), {})[0][0]
            origin = describe_endpoint(room.host, room.port)
            origin["connected"] = True
            store = Store(directory)
            first = store.begin(room, 0)
            store.endpoint(first, origin)
            store.chat(first, origin.copy(), {"message": "早期关键词", "sender": None}, ["关键词"])
            store.finish(first, "listened")

            # 后续运行才发现另一房间跳转到旧端点，旧命中也必须覆盖新端点。
            later_room = replace(room, room_id="later", host="203.0.113.5", port=6123)
            later = describe_endpoint(later_room.host, later_room.port)
            store = Store(directory)
            second = store.begin(later_room, 0)
            store.endpoint(second, later)
            store.redirect(second, {"kind": "packet_178", "from": later, "addresses": [f"{room.host}:{room.port}"]})
            store.endpoint(second, origin)
            store.finish(second, "disconnected")

            groups = json.loads((Path(directory) / "matched_servers.json").read_text(encoding="utf-8"))
            self.assertEqual(1, len(groups))
            self.assertEqual({"203.0.113.4:5123", "203.0.113.5:6123"}, set(groups[0]["ip_ports"]))
            self.assertEqual({first, second}, set(groups[0]["session_ids"]))
            self.assertEqual(1, len(groups[0]["matches"]))
            self.assertTrue(groups[0]["redirected"])

    def test_rate_limiter_rejects_slot_outside_room_budget(self):
        limiter = RateLimiter(10)
        limiter.wait(time.monotonic() + 1)
        with self.assertRaises(TimeoutError):
            limiter.wait(time.monotonic() + 0.1)
