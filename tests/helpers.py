import contextlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path


class OneServer:
    def __init__(self, handler, context=None):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(5)
        self.socket.settimeout(5)
        self.port = self.socket.getsockname()[1]
        self.errors = []

        def run():
            try:
                connection, _ = self.socket.accept()
                connection.settimeout(5)
                if context:
                    connection = context.wrap_socket(connection, server_side=True)
                with connection:
                    handler(connection)
            except BaseException as error:
                self.errors.append(error)

        self.thread = threading.Thread(target=run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.thread.join(6)
        self.socket.close()
        if not args[0] and self.errors:
            raise self.errors[0]
        if self.thread.is_alive():
            raise AssertionError("本地服务器线程未退出")


@contextlib.contextmanager
def tls_contexts():
    if not shutil.which("openssl"):
        import unittest
        raise unittest.SkipTest("TLS 行为测试需要本机 openssl 生成临时证书")
    with tempfile.TemporaryDirectory() as directory:
        key, cert = Path(directory) / "key.pem", Path(directory) / "cert.pem"
        result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
                                 "-out", str(cert), "-sha256", "-days", "1", "-nodes", "-subj", "/CN=localhost",
                                 "-addext", "subjectAltName=DNS:localhost"], capture_output=True)
        if result.returncode:
            raise AssertionError(result.stderr.decode(errors="replace"))
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(cert, key)
        client = ssl.create_default_context(cafile=str(cert))
        yield server, client


def read_header(connection):
    from rwscan.transport import recv_exact
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        result.extend(recv_exact(connection, 1))
    return bytes(result)
