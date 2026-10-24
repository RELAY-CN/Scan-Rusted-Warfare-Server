import hashlib
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs

from rwscan.config import Config
from rwscan.listing import aggregate, exclusion_reason, fetch_rooms, lookup_room, parse_listing
from rwscan.transport import recv_exact
from tests.helpers import OneServer, read_header


def row(room_id="r1", host="203.0.113.4", port=5123, dedicated=False, version=176):
    return ",".join([room_id, "Unnamed", str(version), host, "192.168.0.2", str(port), "false",
                     "玩家中文", "false", "[p8]地图", "skirmishMap", "battleroom", "1.15", "false",
                     "未知保留字段", "2", "8", str(dedicated).lower(), room_id, "true", "", "0"])


class ListingTests(unittest.TestCase):
    def test_parse_real_columns_and_errors(self):
        rooms, errors = parse_listing("CORRODINGGAMES[1.0]\n" + row() + "\nbad,row\n", {"master": "gs1"})
        self.assertEqual(1, len(rooms))
        self.assertEqual(("玩家中文", "[p8]地图", 5123, 176), (rooms[0].name, rooms[0].map_name, rooms[0].port, rooms[0].version_code))
        self.assertFalse(rooms[0].port_open)
        self.assertEqual(1, len(errors))
        self.assertEqual(3, errors[0]["line"])
        with self.assertRaises(ValueError):
            parse_listing("CORRODINGGAMES[FAILED]\nerror", {})

    def test_union_differences_and_discovery(self):
        calls = []

        def fetch(url, params, proxy, timeout):
            calls.append((url, params.copy()))
            if url == "http://gs4/":
                raise OSError("unavailable")
            text = row("plain", version=199) if "game_version" not in params else row("versioned")
            return "CORRODINGGAMES[1.0]\n" + text

        config = Config(masters=["http://gs1/", "http://gs4/"], list_versions=[None, 176], list_betas=[False], discovery_rounds=1)
        rooms, report = fetch_rooms(config, fetcher=fetch)
        self.assertEqual({"plain", "versioned"}, {r.room_id for r in rooms})
        self.assertTrue(any(params.get("game_version") == 199 for _, params in calls))
        self.assertTrue(any(q["error"] for q in report["queries"]))
        difference = next(d for d in report["differences"] if d["game_version"] == 176)
        self.assertEqual(["versioned"], difference["only_versioned"])
        self.assertEqual(["plain"], difference["only_unversioned"])

    def test_exclude_per_room_and_aggregate_multiple_rooms_same_port(self):
        rooms, _ = parse_listing("CORRODINGGAMES\n" + "\n".join([row("official", dedicated=True), row("third"), row("third2", port=5124)]), {})
        selected = [r for r in rooms if exclusion_reason(r, Config()) is None]
        self.assertEqual(2, len(selected))
        self.assertEqual({"5123", "5124"}, set(aggregate(selected)["203.0.113.4"]))
        selected.append(selected[0])
        self.assertEqual(2, len(aggregate(selected)["203.0.113.4"]["5123"]))

    def test_config_rejects_invalid_inputs(self):
        for kwargs in ({"concurrency": 0}, {"proxies": ["ftp://bad"]}, {"listen_seconds": float("nan")}, {"keywords": [""]}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Config(**kwargs).validate()

    def test_get_posts_native_challenge_and_password_hash(self):
        challenge = hashlib.md5(b"x37").hexdigest()[:10]
        password_hash = "room-id密码"
        for _ in range(4):
            password_hash = hashlib.sha256(password_hash.encode()).hexdigest().upper()

        def handler(connection):
            header = read_header(connection)
            self.assertTrue(header.startswith(b"POST /interface HTTP/1.1\r\n"))
            length = int(next(line.split(b":", 1)[1] for line in header.split(b"\r\n")
                              if line.lower().startswith(b"content-length:")))
            params = parse_qs(recv_exact(connection, length).decode())
            self.assertEqual({"action": ["get"], "game_id": ["room-id"], "c": [challenge],
                              "p_hash": [password_hash]}, params)
            checksum = hashlib.sha256(("game_" + challenge).encode()).hexdigest()[:14].upper()
            body = ("CORRODINGGAMES\nOK\n" + checksum + "\n\n" + row("room-id", port=6123)).encode()
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

        with OneServer(handler) as server:
            config = Config(masters=[f"http://127.0.0.1:{server.port}/interface"])
            self.assertEqual(("203.0.113.4", 6123), lookup_room(config, "room-id", 37, "密码"))

    def test_invalid_listing_header_still_preserves_raw_response(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config(masters=["http://gs1/"], list_versions=[None], discover_versions=False)
            rooms, report = fetch_rooms(config, Path(directory), fetcher=lambda *args: "bad header\nerror details")
            self.assertEqual([], rooms)
            self.assertTrue(report["queries"][0]["error"])
            raw_files = list(Path(directory).glob("*.txt"))
            self.assertEqual(1, len(raw_files))
            self.assertEqual("bad header\nerror details", raw_files[0].read_text(encoding="utf-8"))

    def test_blank_player_counts_preserve_room_record(self):
        columns = row("relay", dedicated=True).split(",")
        columns[15] = columns[16] = ""
        rooms, errors = parse_listing("CORRODINGGAMES\n" + ",".join(columns), {})
        self.assertEqual([], errors)
        self.assertEqual(1, len(rooms))
        self.assertIsNone(rooms[0].players)
        self.assertIsNone(rooms[0].max_players)
        self.assertEqual("dedicated", exclusion_reason(rooms[0], Config()))
