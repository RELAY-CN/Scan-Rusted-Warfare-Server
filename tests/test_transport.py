import base64
import socket
import threading
import time
import unittest

from rwscan.listing import request_text
from rwscan.transport import TLSStream, TransportError, open_connection, recv_exact
from tests.helpers import OneServer, read_header, tls_contexts


class TransportTests(unittest.TestCase):
    def test_direct_and_exact_partial_receive(self):
        def handler(connection):
            self.assertEqual(b"hello", recv_exact(connection, 5))
            connection.sendall(b"ab")
            connection.sendall(b"cd")

        with OneServer(handler) as server:
            connection = open_connection("127.0.0.1", server.port, "direct", 2)
            with connection:
                connection.sendall(b"hello")
                self.assertEqual(b"abcd", recv_exact(connection, 4))
                with self.assertRaises(EOFError):
                    recv_exact(connection, 1)

    def test_http_connect_auth_preserves_following_payload(self):
        def handler(connection):
            header = read_header(connection)
            self.assertIn(b"CONNECT example.net:5123 HTTP/1.1", header)
            self.assertIn(b"Proxy-Authorization: Basic " + base64.b64encode(b"user:p@ss"), header)
            connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\nGAME")

        with OneServer(handler) as server:
            connection = open_connection("example.net", 5123, f"http://user:p%40ss@127.0.0.1:{server.port}", 2)
            with connection:
                self.assertEqual(b"GAME", recv_exact(connection, 4))

    def test_http_rejection(self):
        def handler(connection):
            read_header(connection)
            connection.sendall(b"HTTP/1.1 407 Authentication required\r\n\r\n")

        with OneServer(handler) as server, self.assertRaises(TransportError):
            open_connection("example.net", 5123, f"http://127.0.0.1:{server.port}", 2)

    def test_socks4a_and_socks5_authenticated_domain(self):
        def socks4(connection):
            self.assertEqual(b"\x04\x01\x14\x03\x00\x00\x00\x01", recv_exact(connection, 8))
            self.assertEqual(b"user\x00example.net\x00", recv_exact(connection, 17))
            connection.sendall(b"\x00\x5a\x00\x00\x00\x00\x00\x00X")

        with OneServer(socks4) as server:
            connection = open_connection("example.net", 5123, f"socks4://user@127.0.0.1:{server.port}", 2)
            with connection:
                self.assertEqual(b"X", recv_exact(connection, 1))

        def socks5(connection):
            self.assertEqual(b"\x05\x02\x00\x02", recv_exact(connection, 4))
            connection.sendall(b"\x05\x02")
            self.assertEqual(b"\x01\x04user\x04pass", recv_exact(connection, 11))
            connection.sendall(b"\x01\x00")
            self.assertEqual(b"\x05\x01\x00\x03\x0bexample.net\x14\x03", recv_exact(connection, 18))
            connection.sendall(b"\x05\x00\x00\x04" + b"\x00" * 16 + b"\x14\x03X")

        with OneServer(socks5) as server:
            connection = open_connection("example.net", 5123, f"socks5://user:pass@127.0.0.1:{server.port}", 2)
            with connection:
                self.assertEqual(b"X", recv_exact(connection, 1))

    def test_https_proxy_and_nested_target_tls(self):
        with tls_contexts() as (server_context, client_context):
            def handler(connection):
                self.assertIn(b"CONNECT localhost:5123", read_header(connection))
                connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\nTLSGAME")

            with OneServer(handler, server_context) as proxy:
                connection = open_connection("localhost", 5123, f"https://localhost:{proxy.port}", 3, tls_context=client_context)
                try:
                    self.assertEqual(b"TLSGAME", recv_exact(connection, 7))
                finally:
                    connection.close()

            def target_handler(connection):
                header = read_header(connection)
                self.assertIn(b"GET /interface?action=list", header)
                body = "CORRODINGGAMES\n中文".encode()
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

            with OneServer(target_handler, server_context) as target:
                def proxy_handler(connection):
                    read_header(connection)
                    connection.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                    with socket.create_connection(("127.0.0.1", target.port), 3) as downstream:
                        upload_errors = []
                        def upload():
                            try:
                                while data := connection.recv(65536):
                                    downstream.sendall(data)
                            except OSError as error:
                                upload_errors.append(error)

                        worker = threading.Thread(target=upload, daemon=True)
                        worker.start()
                        while data := downstream.recv(65536):
                            connection.sendall(data)
                        worker.join(4)
                        self.assertFalse(worker.is_alive())
                        self.assertEqual([], upload_errors)

                with OneServer(proxy_handler, server_context) as proxy:
                    result = request_text(f"https://localhost:{target.port}/interface", {"action": "list"},
                                          f"https://localhost:{proxy.port}", 3, tls_context=client_context)
                    self.assertEqual("CORRODINGGAMES\n中文", result)

    def test_http_listing_chunks_and_status_error(self):
        def handler(connection):
            header = read_header(connection)
            self.assertIn(b"game_version=176", header)
            connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")

        with OneServer(handler) as server:
            self.assertEqual("abcde", request_text(f"http://127.0.0.1:{server.port}/interface", {"game_version": 176}, "direct", 2))

    def test_socks_handshake_has_one_total_timeout(self):
        def handler(connection):
            self.assertEqual(b"\x05\x01\x00", recv_exact(connection, 3))
            # 每个分片都早于单次 socket 超时，但完整握手超过总预算。
            connection.sendall(b"\x05\x00")
            recv_exact(connection, 10)
            try:
                for byte in b"\x05\x00\x00\x01" + b"\x00" * 6:
                    time.sleep(0.06)
                    connection.sendall(bytes([byte]))
            except OSError:
                # 客户端按预期超时关闭后，服务器可能收到 BrokenPipe/Reset。
                return

        with OneServer(handler) as server:
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                stream = open_connection("127.0.0.1", 5123, f"socks5://127.0.0.1:{server.port}", 0.2)
                stream.close()
            self.assertLess(time.monotonic() - started, 0.5)
