import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scripts import net


class FlakyServer:
    """Local HTTP server that answers with the queued status codes, then 200."""

    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.hits = 0
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                server.hits += 1
                status = server.statuses.pop(0) if server.statuses else 200
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def flaky(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    servers = []

    def make(*statuses):
        server = FlakyServer(statuses)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def test_transient_server_error_is_retried(flaky):
    server = flaky(503)

    response = net.http_get(server.url)

    assert response.status_code == 200
    assert server.hits == 2


def test_nvd_rate_limit_403_is_retried(flaky):
    server = flaky(403)

    response = net.http_get(server.url, nvd=True)

    assert response.status_code == 200
    assert server.hits == 2


def test_403_is_not_retried_for_other_apis(flaky):
    # Outside NVD a 403 means a bad key or no access: retrying would only waste time
    server = flaky(403)

    response = net.http_get(server.url)

    assert response.status_code == 403
    assert server.hits == 1


def test_gives_up_after_max_retries(monkeypatch, flaky):
    monkeypatch.setattr(net, "BACKOFF_FACTOR", 0)
    monkeypatch.setattr(net, "_local", threading.local())  # rebuild sessions with the patched backoff
    server = flaky(*([503] * 10))

    response = net.http_get(server.url)

    assert response.status_code == 503
    assert server.hits == net.MAX_RETRIES + 1


def test_every_request_has_a_timeout(monkeypatch):
    seen = {}

    class FakeSession:
        def get(self, url, **kwargs):
            seen.update(kwargs)

    monkeypatch.setattr(net, "_session", lambda nvd: FakeSession())
    net.http_get("https://example.invalid")

    assert seen["timeout"] == net.DEFAULT_TIMEOUT


def test_unreachable_host_fails_fast(monkeypatch):
    import socket
    import time

    import requests

    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    # Grab a free port and close it so nothing is listening there
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    started = time.monotonic()
    try:
        net.http_get(f"http://127.0.0.1:{port}/")
        raise AssertionError("expected a connection error")
    except requests.exceptions.ConnectionError:
        pass

    assert time.monotonic() - started < 3
