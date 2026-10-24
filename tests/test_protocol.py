import hashlib
import struct
import unittest

from rwscan.config import Config
from rwscan.protocol import Reader, Writer, ProtocolError, connect_key, preregister, register, challenge_reply, parse_address, decode_chat, decode_redirect


class ProtocolTests(unittest.TestCase):
    def test_modified_utf_matches_java_encoding(self):
        value = "A\x00中😀"
        expected = bytes.fromhex("000c41c080e4b8adeda0bdedb880")
        self.assertEqual(expected, Writer().utf(value).data)
        self.assertEqual(value, Reader(expected).utf())
        with self.assertRaises(ProtocolError):
            Reader(b"\x00\x04\xf0\x9f\x98\x80").utf()
        with self.assertRaises(ProtocolError):
            Reader(b"\x00\x05abc").utf()

    def test_native_registration_and_int_overflow(self):
        r = Reader(preregister(Config(), "query").data)
        self.assertEqual("com.corrodinggames.rts", r.utf())
        self.assertEqual((4, 176, 1, "query", "RoomScanner", "zh", ""), (r.int(), r.int(), r.int(), r.optional_utf(), r.utf(), r.utf(), r.utf()))
        self.assertEqual("c:1m:1110:440001:12:130003:280014:750005:1600016:8500007:18000008:3800000t1:44000.0d:5", connect_key(1))
        self.assertIn("m:2147483585", connect_key(2147483647))
        r = Reader(register(Config(), "client", "server", 1, 0x1234567, "密码").data)
        self.assertEqual("com.corrodinggames.rts", r.utf())
        self.assertEqual((5, 176, 176, "RoomScanner"), (r.int(), r.int(), r.int(), r.utf()))
        self.assertEqual(hashlib.sha256("密码".encode()).hexdigest().upper(), r.optional_utf())
        self.assertEqual("com.corrodinggames.rts", r.utf())
        self.assertEqual(hashlib.sha256(b"clientserver").hexdigest().upper(), r.utf())
        self.assertEqual(678359601, r.int())
        self.assertEqual(connect_key(1), r.utf())
        self.assertEqual("#234567", r.utf())

    def test_chat_and_redirect_layout(self):
        data = Writer().utf("包含关键词").byte(3).optional_utf(None).int(7).int(-1).data
        self.assertEqual({"message": "包含关键词", "sender": None, "connection_index": 7, "site": -1}, decode_chat(data))
        redirect = Writer().byte(0).int(3).boolean(False).int(2).utf("[TCP]example.net:6000/room").utf("203.0.113.1:5123").data
        self.assertEqual(["[TCP]example.net:6000/room", "203.0.113.1:5123"], decode_redirect(redirect)["addresses"])
        with self.assertRaises(ProtocolError):
            decode_redirect(Writer().byte(0).int(3).boolean(False).int(-1).data)

    def test_connect_address_formats(self):
        self.assertEqual(("example.net", 6000, "room"), parse_address("[TCP]example.net:6000/room"))
        self.assertEqual(("a.relay.corrodinggames.com", 5123, "abcde"), parse_address("abcde"))
        self.assertEqual(("a.relay.corrodinggames.com", 5123, None), parse_address("a.relay"))
        self.assertEqual(("2001:db8::1", 6000, None), parse_address("[2001:db8::1]:6000"))
        with self.assertRaises(ProtocolError):
            parse_address("host:70000")

    def test_challenge_types_and_work_budget(self):
        config = Config(max_challenge_iterations=100)
        for kind, expected in [(0, "12"), (1, "34"), (2, connect_key(12)), (3, hashlib.sha256(b"12|34").hexdigest().upper()[:14])]:
            payload = Writer().int(9).int(kind).boolean(True).int(12).boolean(True).int(34).data
            output, a, b = challenge_reply(payload, 0, 0, config)
            r = Reader(output.data)
            self.assertEqual((9, kind, expected), (r.int(), r.int(), r.utf()))
            self.assertEqual((12, 34), (a, b))
        target = hashlib.sha256(b"prefix3").hexdigest().upper()[:14]
        payload = Writer().int(2).int(5).boolean(False).boolean(False).utf(target).utf("prefix").int(4).data
        output, _, _ = challenge_reply(payload, 0, 0, config)
        r = Reader(output.data)
        r.int(); r.int()
        self.assertEqual("3", r.utf())
        payload = Writer().int(2).int(5).boolean(False).boolean(False).utf(target).utf("prefix").int(101).data
        with self.assertRaises(ProtocolError):
            challenge_reply(payload, 0, 0, config)
