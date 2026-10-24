import contextlib
import csv
import hashlib
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
def list_server(fail_paths=(), *, targets=None, get_fail_ids=(), get_requests=None):
    requests = []
    get_requests = [] if get_requests is None else get_requests
    targets = {"unversioned": ("127.0.0.2", 6123), "versioned": ("127.0.0.3", 7123),
               "same-port": ("127.0.0.2", 6124)} if targets is None else targets

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

        def do_POST(self):
            params = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode(), keep_blank_values=True)
            get_requests.append(params)
            room_id = params["game_id"][0]
            if urlsplit(self.path).path in fail_paths or room_id in get_fail_ids:
                self.send_error(503)
                return
            host, port = targets[room_id]
            checksum = hashlib.sha256(("game_" + params["c"][0]).encode()).hexdigest()[:14]
            body = ("CORRODINGGAMES\nOK\n" + checksum + "\n\n" + row(room_id, host, port)).encode()
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
        get_requests = []
        with list_server(get_requests=get_requests) as (url, requests):
            self.config(masters=[url + "/gs1", url + "/gs4"])
            result = self.cli("list")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual({None, "176"}, {p.get("game_version", [None])[0] for _, p in requests})
            inventory = json.loads((self.output / "rooms.json").read_text(encoding="utf-8"))
            self.assertEqual({"unversioned", "versioned", "same-port"}, {r["room_id"] for r in inventory["rooms"]})
            self.assertEqual({"127.0.0.2", "127.0.0.3"}, set(inventory["by_ip"]))
            self.assertEqual({"6123", "6124"}, set(inventory["by_ip"]["127.0.0.2"]))
            self.assertEqual({"unversioned", "versioned", "same-port"}, {r["game_id"][0] for r in get_requests})
            self.assertTrue(all(r["action"] == ["get"] and r["c"] == [""] for r in get_requests))
            self.assertTrue(all(r["listed_host"] == "127.0.0.1" and r["lookup_status"] == "resolved" for r in inventory["rooms"]))
            self.assertEqual("dedicated", inventory["excluded"][0]["reason"])
            self.assertTrue(inventory["report"]["differences"])
            self.assertTrue((self.output / "rooms.csv").exists())
            self.assertEqual(4, len(list((self.output / "raw").glob("*.txt"))))
            with (self.output / "rooms.csv").open(encoding="utf-8-sig", newline="") as handle:
                self.assertEqual({("127.0.0.2", "6123"), ("127.0.0.2", "6124"), ("127.0.0.3", "7123")},
                                 {(r["ip"], r["port"]) for r in csv.DictReader(handle)})

    def test_get_failure_is_preserved_without_aggregating_placeholder(self):
        with list_server(get_fail_ids={"versioned"}) as (url, _):
            self.config(masters=[url + "/gs1", url + "/gs4"])
            self.assertEqual(2, self.cli("list").returncode)
            inventory = json.loads((self.output / "rooms.json").read_text(encoding="utf-8"))
            self.assertEqual({"127.0.0.2"}, set(inventory["by_ip"]))
            failed = next(r for r in inventory["rooms"] if r["room_id"] == "versioned")
            self.assertEqual("failed", failed["lookup_status"])
            self.assertTrue(failed["lookup_error"])
            self.assertEqual(1, sum(q["status"] == "failed" for q in inventory["report"]["get_queries"]))

    def test_include_official_still_skips_get_and_filters_real_ip(self):
        get_requests = []
        with list_server(get_requests=get_requests) as (url, _):
            self.config(masters=[url + "/gs1", url + "/gs4"], exclude_ips=["127.0.0.3"])
            self.assertEqual(0, self.cli("list", "--include-dedicated").returncode)
            inventory = json.loads((self.output / "rooms.json").read_text(encoding="utf-8"))
            self.assertEqual({"127.0.0.1", "127.0.0.2"}, set(inventory["by_ip"]))
            official = next(r for r in inventory["rooms"] if r["room_id"] == "official")
            self.assertEqual("official", official["lookup_status"])
            self.assertEqual({"unversioned", "versioned", "same-port"}, {r["game_id"][0] for r in get_requests})
            self.assertEqual("ip", inventory["excluded"][0]["reason"])

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
        room.lookup_status = "resolved"
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

    def test_scan_legacy_file_resolves_get_without_merging_public_entry(self):
        def handler(connection):
            receive_packet(connection, 100000)
            send_packet(connection, 161, Writer().utf("server").int(2).int(176).int(176)
                        .utf("server").utf("uuid").int(1).int(0).int(0))
            receive_packet(connection, 100000)
            send_packet(connection, 106, Writer().utf("server").int(176).int(0).utf("实际地图"))
            send_packet(connection, 141, Writer().utf("关键词").byte(3).optional_utf(None).int(0).int(-1))
            send_packet(connection, 111, Writer().utf("done"))
            receive_packet(connection, 100000)

        with OneServer(handler) as first, OneServer(handler) as second:
            targets = {"local-a": ("127.0.0.1", first.port), "local-b": ("127.0.0.1", second.port)}
            get_requests = []
            with list_server(targets=targets, get_requests=get_requests) as (url, _):
                self.config(masters=[url + "/gs1"])
                rooms = parse_listing("CORRODINGGAMES\n" + "\n".join(row(r, "127.0.0.9", 5158) for r in targets), {})[0]
                data = [r.to_dict() for r in rooms]
                for room in data:
                    for key in ("listed_host", "listed_port", "lookup_status", "lookup_error"):
                        room.pop(key, None)
                path = self.root / "legacy-rooms.json"
                path.write_text(json.dumps({"rooms": data}), encoding="utf-8")
                result = self.cli("scan", "--rooms-file", str(path))
                self.assertEqual(0, result.returncode, result.stderr)
                groups = json.loads((self.output / "matched_servers.json").read_text(encoding="utf-8"))
                self.assertEqual(2, len(groups))
                self.assertEqual({(f"127.0.0.1:{first.port}",), (f"127.0.0.1:{second.port}",)},
                                 {tuple(g["ip_ports"]) for g in groups})
                self.assertTrue(all(not g["redirected"] for g in groups))
                self.assertTrue(all(g["rooms"][0]["listed_host"] == "127.0.0.9" for g in groups))
                self.assertEqual({"local-a", "local-b"}, {r["game_id"][0] for r in get_requests})

    def test_scan_legacy_file_filters_get_ip_before_connecting(self):
        with list_server(targets={"local": ("127.0.0.3", 5123)}) as (url, _):
            self.config(masters=[url + "/gs1"], exclude_ips=["127.0.0.3"])
            room = parse_listing("CORRODINGGAMES\n" + row("local", "127.0.0.9", 5158), {})[0][0]
            path = self.root / "rooms.json"
            path.write_text(json.dumps({"rooms": [room.to_dict()]}), encoding="utf-8")
            result = self.cli("scan", "--rooms-file", str(path))
            self.assertEqual(0, result.returncode, result.stderr)
            sessions = json.loads((self.output / "sessions.json").read_text(encoding="utf-8"))
            session = next(iter(sessions.values()))
            self.assertEqual("excluded", session["status"])
            self.assertEqual("ip", session["exclusion_reason"])
            self.assertEqual([], session["endpoints"])

    def test_scan_get_failure_records_no_placeholder_endpoint(self):
        with list_server(get_fail_ids={"local"}) as (url, _):
            self.config(masters=[url + "/gs1"])
            room = parse_listing("CORRODINGGAMES\n" + row("local", "127.0.0.9", 5158), {})[0][0]
            path = self.root / "rooms.json"
            path.write_text(json.dumps({"rooms": [room.to_dict()]}), encoding="utf-8")
            result = self.cli("scan", "--rooms-file", str(path))
            self.assertEqual(2, result.returncode, result.stderr)
            sessions = json.loads((self.output / "sessions.json").read_text(encoding="utf-8"))
            session = next(iter(sessions.values()))
            self.assertEqual("lookup_failed", session["status"])
            self.assertEqual("failed", session["room"]["lookup_status"])
            self.assertTrue(session["room"]["lookup_error"])
            self.assertEqual([], session["endpoints"])
            self.assertEqual([], session["redirects"])
