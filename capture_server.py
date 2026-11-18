"""A tiny local E2B API stub that records the SDK's exact requests."""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class CaptureState:
    def __init__(
        self,
        log_path: Path,
        retry_failures: int = 0,
        delay: float = 0.0,
        *,
        valid_error_body: bool = True,
        include_optional_response_fields: bool = True,
        failure_status: int = 503,
        failure_retry_header: str | None = "true",
    ):
        self.log_path = log_path
        self.retry_failures = retry_failures
        self.delay = delay
        self.valid_error_body = valid_error_body
        self.include_optional_response_fields = include_optional_response_fields
        self.failure_status = failure_status
        self.failure_retry_header = failure_retry_header
        self.sandboxes: set[str] = set()
        self.next_id = 1
        self.lock = threading.Lock()


class CaptureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: CaptureState):
        super().__init__(address, CaptureHandler)
        self.state = state

    def handle_error(self, request: Any, client_address: Any) -> None:
        import sys

        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionAbortedError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


class CaptureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> CaptureState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def _record(
        self,
        body: bytes,
        status: int,
        response_body: Any,
        response_headers: dict[str, str] | None = None,
    ) -> None:
        try:
            decoded_body: Any = json.loads(body.decode("utf-8")) if body else None
        except Exception:
            decoded_body = body.decode("utf-8", errors="replace")
        record = {
            "timestamp": time.time(),
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers.items()),
            "body": decoded_body,
            "response_status": status,
            "response_headers": response_headers or {},
            "response_body": response_body,
        }
        with self.state.lock:
            with self.state.log_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _error_body(self, status: int, message: str) -> dict[str, Any]:
        if self.state.valid_error_body:
            return {"code": status, "message": message}
        return {"message": message}

    def _send_json(
        self, status: int, payload: Any, headers: dict[str, str] | None = None
    ) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def _send_empty(self, status: int) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    @staticmethod
    def _route_key(path: str) -> str:
        """Return the SDK route while ignoring an optional deployment prefix."""
        if path.endswith("/v2/sandboxes"):
            return "/v2/sandboxes"
        marker = "/sandboxes/"
        if marker in path:
            return path[path.index(marker):]
        return path

    def do_POST(self) -> None:
        body = self._read_body()
        if self.state.delay:
            time.sleep(self.state.delay)

        route = self._route_key(urlparse(self.path).path)
        if route != "/v2/sandboxes":
            response = self._error_body(404, "not found")
            response_headers = {"Content-Type": "application/json"}
            self._record(body, 404, response, response_headers)
            self._send_json(404, response)
            return

        with self.state.lock:
            if self.state.retry_failures > 0:
                self.state.retry_failures -= 1
                should_retry = True
            else:
                should_retry = False

        if should_retry:
            response = self._error_body(
                self.state.failure_status,
                "failure requested by capture server",
            )
            extra_headers: dict[str, str] = {}
            if self.state.failure_retry_header is not None:
                extra_headers["Should-Retry"] = self.state.failure_retry_header
            response_headers = {"Content-Type": "application/json", **extra_headers}
            self._record(
                body,
                self.state.failure_status,
                response,
                response_headers,
            )
            self._send_json(self.state.failure_status, response, extra_headers)
            return

        with self.state.lock:
            sandbox_id = f"sbx_trace_{self.state.next_id:03d}"
            self.state.next_id += 1
            self.state.sandboxes.add(sandbox_id)

        response: dict[str, Any] = {
            "templateID": "base",
            "sandboxID": sandbox_id,
            "clientID": "client_trace",
            "envdVersion": "0.8.0",
        }
        if self.state.include_optional_response_fields:
            response.update(
                {
                    "envdAccessToken": "envd-access-token",
                    "trafficAccessToken": None,
                    "domain": "sandbox.example.test",
                }
            )
        self._record(
            body,
            201,
            response,
            {"Content-Type": "application/json"},
        )
        self._send_json(201, response)

    def do_DELETE(self) -> None:
        body = self._read_body()
        path = self._route_key(urlparse(self.path).path)
        prefix = "/sandboxes/"
        sandbox_id = path[len(prefix):] if path.startswith(prefix) else ""

        if not sandbox_id:
            response = self._error_body(404, "not found")
            self._record(
                body,
                404,
                response,
                {"Content-Type": "application/json"},
            )
            self._send_json(404, response)
            return

        with self.state.lock:
            existed = sandbox_id in self.state.sandboxes
            if existed:
                self.state.sandboxes.remove(sandbox_id)

        if existed:
            self._record(body, 204, None, {"Content-Length": "0"})
            self._send_empty(204)
        else:
            response = self._error_body(404, "Sandbox not found")
            self._record(
                body,
                404,
                response,
                {"Content-Type": "application/json"},
            )
            self._send_json(404, response)

    def do_GET(self) -> None:
        if urlparse(self.path).path.endswith("/healthz"):
            self._record(
                b"",
                200,
                {"status": "ok"},
                {"Content-Type": "application/json"},
            )
            self._send_json(200, {"status": "ok"})
        else:
            response = self._error_body(404, "not found")
            self._record(
                b"",
                404,
                response,
                {"Content-Type": "application/json"},
            )
            self._send_json(404, response)


def start_capture_server(
    log_path: Path,
    *,
    port: int = 0,
    retry_failures: int = 0,
    delay: float = 0.0,
    valid_error_body: bool = True,
    include_optional_response_fields: bool = True,
    failure_status: int = 503,
    failure_retry_header: str | None = "true",
) -> tuple[CaptureServer, threading.Thread, str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")
    state = CaptureState(
        log_path,
        retry_failures=retry_failures,
        delay=delay,
        valid_error_body=valid_error_body,
        include_optional_response_fields=include_optional_response_fields,
        failure_status=failure_status,
        failure_retry_header=failure_retry_header,
    )
    server = CaptureServer(("127.0.0.1", port), state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, actual_port = server.server_address
    return server, thread, f"http://{host}:{actual_port}"


def stop_capture_server(server: CaptureServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, default=Path("samples/capture.jsonl"))
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--retry-failures", type=int, default=0)
    parser.add_argument("--delay", type=float, default=0.0)
    args = parser.parse_args()
    server, thread, url = start_capture_server(
        args.log,
        port=args.port,
        retry_failures=args.retry_failures,
        delay=args.delay,
    )
    print(f"capture server listening at {url}; log={args.log}")
    try:
        thread.join()
    except KeyboardInterrupt:
        stop_capture_server(server, thread)


if __name__ == "__main__":
    main()
