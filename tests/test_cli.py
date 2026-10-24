import contextlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from rwscan.listing import parse_listing
from rwscan.protocol import Reader, Writer, receive_packet, send_packet
from tests.helpers import OneServer
from tests.test_listing import row


@contextlib.contextmanager
def list_server(fail_paths=()):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlsplit(self.path)
            params = parse_qs(parsed.query)
            requests.append((parsed.path, params))
            if parsed.path in fail_paths:
                self.send_error(503)
                return
            if parsed.path == "/gs1":
                records = [row("versioned" if "game_version" in params else "unversioned", "127.0.0.1")]
            else:
                records = [row("official", "127.0.0.1", dedicated=True), row("same-port", "127.0.0.1")]
            body = ("CORRODINGGAMES\n" + "\n".join(records)).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(3)
        if worker.is_alive():
            raise AssertionError("本地列表服务器未退出")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "config.json"
        self.output = self.root / "output"

    def config(self, **overrides):
        data = {"output_dir": str(self.output), "list_versions": [None, 176], "list_betas": [False],
                "discover_versions": False, "keywords": ["关键词"], "join_interval": 0, "listen_seconds": 2}
        data.update(overrides)
        self.config_path.write_text(json.dumps(data), encoding="utf-8")

    def cli(self, *args):
        result = subprocess.run([sys.executable, "-m", "rwscan", *args, "--config", str(self.config_path)],
                                cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
                                encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"}, timeout=10)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def test_list_cli_unions_versions_filters_official_and_writes_inventory(self):
        with list_server() as (url, requests):
            self.config(masters=[url + "/gs1", url + "/gs4"])
            result = self.cli("list")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual({None, "176"}, {p.get("game_version", [None])[0] for _, p in requests})
            inventory = json.loads((self.output / "rooms.json").read_text(encoding="utf-8"))
            self.assertEqual({"unversioned", "versioned", "same-port"}, {r["room_id"] for r in inventory["rooms"]})
            self.assertEqual(3, len(inventory["by_ip"]["127.0.0.1"]["5123"]))
            self.assertEqual("dedicated", inventory["excluded"][0]["reason"])
            self.assertTrue(inventory["report"]["differences"])
            self.assertTrue((self.output / "rooms.csv").exists())
            self.assertEqual(4, len(list((self.output / "raw").glob("*.txt"))))

    def test_list_cli_reports_partial_and_total_failure(self):
        with list_server(fail_paths={"/gs4"}) as (url, _):
            self.config(masters=[url + "/gs1", url + "/gs4"])
            self.assertEqual(2, self.cli("list").returncode)
            report = json.loads((self.output / "fetch_report.json").read_text(encoding="utf-8"))
            self.assertEqual(2, sum(bool(q["error"]) for q in report["queries"]))
            self.config(masters=[url + "/gs4"])
            self.assertEqual(1, self.cli("list").returncode)

    def rooms_file(self, port):
        room = parse_listing("CORRODINGGAMES\n" + row("local", "127.0.0.1", port), {})[0][0]
        path = self.root / "rooms.json"
        path.write_text(json.dumps({"rooms": [room.to_dict()]}), encoding="utf-8")
        return path

    def test_scan_cli_from_file_matches_chat_and_answers_relay_dialog(self):
        def handler(connection):
            self.assertEqual(160, receive_packet(connection, 100000)[0])
            send_packet(connection, 161, Writer().utf("server").int(2).int(176).int(176)
                        .utf("server").utf("uuid").int(1).int(0).int(0))
            self.assertEqual(110, receive_packet(connection, 100000)[0])
            send_packet(connection, 106, Writer().utf("server").int(176).int(0).utf("实际地图"))
            send_packet(connection, 117, Writer().byte(1).int(5).utf("请输入房间码"))
            kind, payload = receive_packet(connection, 100000)
            r = Reader(payload)
            self.assertEqual((118, 1, 5, "指定输入"), (kind, r.byte(), r.int(), r.utf()))
            send_packet(connection, 141, Writer().utf("玩家聊天包含关键词").byte(3).optional_utf("玩家").int(1).int(0))
            send_packet(connection, 111, Writer().utf("done"))
            self.assertEqual(111, receive_packet(connection, 100000)[0])

        with OneServer(handler) as server:
            self.config(relay_inputs={"local:5": "指定输入"})
            result = self.cli("scan", "--rooms-file", str(self.rooms_file(server.port)), "--room-id", "local", "--limit", "1")
            self.assertEqual(0, result.returncode, result.stderr)
            groups = json.loads((self.output / "matched_servers.json").read_text(encoding="utf-8"))
            self.assertEqual([f"127.0.0.1:{server.port}"], groups[0]["ip_ports"])
            self.assertEqual("实际地图", groups[0]["rooms"][0]["observed_map"])
            self.assertEqual(["关键词"], groups[0]["matches"][0]["keywords"])

    def test_scan_cli_treats_close_before_join_confirmation_as_failure(self):
        for reason in ("eof", "rejection"):
            with self.subTest(reason=reason):
                def handler(connection):
                    receive_packet(connection, 100000)
                    if reason == "rejection":
                        send_packet(connection, 111, Writer().utf("版本不兼容"))
                    else:
                        connection.shutdown(socket.SHUT_WR)
                    receive_packet(connection, 100000)

                with OneServer(handler) as server:
                    self.config()
                    result = self.cli("scan", "--rooms-file", str(self.rooms_file(server.port)))
                    self.assertEqual(2, result.returncode, result.stdout)

    def test_scan_cli_rejects_missing_keywords_without_network_access(self):
        self.config(keywords=[])
        result = self.cli("scan")
        self.assertEqual(1, result.returncode)
        self.assertIn("keywords", result.stderr)
