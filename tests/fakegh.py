"""A local fake of the slice of api.github.com that pin_actions_plan uses (real HTTP, real sockets)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SHA_V1 = "1" * 40
SHA_TAG_OBJ = "a" * 40
SHA_V2_COMMIT = "2" * 40
SHA_MAIN = "3" * 40
SHA_MOVED = "4" * 40
RESET = 1893456000  # 2030-01-01T00:00:00Z


class FakeGitHub:
    def __init__(self, other_host_port: int = 1) -> None:
        self.requests: list[tuple[str, str | None]] = []  # (path, Authorization header)
        self.other_host_port = other_host_port
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:  # silence
                pass

            def _send(self, code: int, body: object, headers: dict[str, str] | None = None) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                path = self.path
                outer.requests.append((path, self.headers.get("Authorization")))
                if path == "/repos/acme/tool/git/ref/tags/v1":
                    return self._send(200, {"object": {"sha": SHA_V1, "type": "commit"}})
                if path == "/repos/acme/tool/git/ref/tags/v2":
                    return self._send(200, {"object": {"sha": SHA_TAG_OBJ, "type": "tag"}})
                if path == f"/repos/acme/tool/git/tags/{SHA_TAG_OBJ}":
                    return self._send(200, {"object": {"sha": SHA_V2_COMMIT, "type": "commit"}})
                if path == "/repos/acme/tool/git/ref/heads/main":
                    return self._send(200, {"object": {"sha": SHA_MAIN, "type": "commit"}})
                if path.startswith("/repos/rate/limited/"):
                    return self._send(403, {"message": "API rate limit exceeded"},
                                      {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(RESET)})
                if path.startswith("/repos/evil/redirect/"):
                    return self._send(301, {}, {"Location": f"http://127.0.0.1:{outer.other_host_port}/stolen"})
                if path.startswith("/repos/old/name/"):
                    return self._send(301, {}, {"Location": path.replace("/repos/old/name", "/repositories/99")})
                if path == "/repositories/99/git/ref/tags/v1":
                    return self._send(200, {"object": {"sha": SHA_MOVED, "type": "commit"}})
                if path.startswith("/repos/bad/token/"):
                    return self._send(401, {"message": "Bad credentials"})
                return self._send(404, {"message": "Not Found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port: int = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> FakeGitHub:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)
