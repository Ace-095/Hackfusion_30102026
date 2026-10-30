"""Test helpers shipped with TargetLab: serve the lab over loopback TLS.

Everything binds to 127.0.0.1 with an ephemeral port. No external network is
involved, and no test uses these helpers to reach anything but loopback.
"""
from __future__ import annotations

import http.server
import socket
import ssl
import threading
import time
from pathlib import Path

import uvicorn

from targetlab.app import create_lab_app

TLS_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "tls"
TARGETLAB_CERT = TLS_DIR / "targetlab-cert.pem"
TARGETLAB_KEY = TLS_DIR / "targetlab-key.pem"
OTHER_CERT = TLS_DIR / "test-cert.pem"
OTHER_KEY = TLS_DIR / "test-key.pem"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LabTlsServer:
    """The real TargetLab application served over HTTPS on loopback."""

    def __init__(self, cert=TARGETLAB_CERT, key=TARGETLAB_KEY, app=None):
        self.port = free_port()
        self._config = uvicorn.Config(app if app is not None else create_lab_app(),
                                      host="127.0.0.1", port=self.port,
                                      ssl_certfile=str(cert), ssl_keyfile=str(key),
                                      log_level="error", lifespan="off", access_log=False)
        self._server = uvicorn.Server(self._config)
        self._thread = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.time() + 30
        while not self._server.started and time.time() < deadline:
            if not self._thread.is_alive():
                raise RuntimeError("TargetLab TLS server thread exited during startup")
            time.sleep(0.05)
        if not self._server.started:
            raise RuntimeError("TargetLab TLS server did not start")
        return self

    def __exit__(self, *exc):
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=15)
        return False


class _CountingHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - required by BaseHTTPRequestHandler
        type(self).hits += 1
        if type(self).status != 200:
            body = b'{"error":"synthetic"}'
            self.send_response(type(self).status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if type(self).redirect:
            self.send_response(302)
            self.send_header("Location", "https://example.com/steal")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence the default stderr logging
        return


class CountingTlsServer:
    """A minimal TLS server that counts requests and can answer with a redirect."""

    def __init__(self, *, redirect: bool = False, status: int = 200):
        self.port = free_port()
        handler = type("CountingHandler", (_CountingHandler,),
                       {"hits": 0, "redirect": redirect, "status": status})
        self._handler = handler
        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(TARGETLAB_CERT), str(TARGETLAB_KEY))
        self._httpd.socket = context.wrap_socket(self._httpd.socket, server_side=True)
        self._thread = None

    @property
    def hits(self) -> int:
        return self._handler.hits

    def __enter__(self):
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
        return False
