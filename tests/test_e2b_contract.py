from __future__ import annotations

import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import httpx
import pytest
from e2b import Sandbox

from capture_server import start_capture_server, stop_capture_server


API_KEY = "e2b_test_key"


@contextmanager
def capture_at(tmp_path: Path, **server_options: Any) -> Iterator[dict[str, Any]]:
    log_path = tmp_path / "capture.jsonl"
    server, thread, root_url = start_capture_server(
        log_path,
        **server_options,
    )
    state: dict[str, Any] = {"url": root_url, "log_path": log_path}
    try:
        yield state
    finally:
        stop_capture_server(server, thread)


def read_requests(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def create_sandbox(base_url: str, **kwargs: Any) -> Sandbox:
    return Sandbox.create(
        api_key=API_KEY,
        api_url=base_url,
        http_version="1.1",
        retries=0,
        **kwargs,
    )


def header_value(headers: dict[str, str], name: str) -> str | None:
    matches = [value for key, value in headers.items() if key.lower() == name.lower()]
    return matches[0] if matches else None


def test_create_request_and_response_mapping(tmp_path: Path) -> None:
    with capture_at(tmp_path) as capture:
        sandbox = create_sandbox(
            capture["url"] + "/compat/e2b",
            template="trace-template",
            timeout=42,
            metadata={"purpose": "contract-capture", "run": "local"},
            envs={"FOO": "bar", "EMPTY": ""},
            idempotency_key="trace-create-001",
        )

        requests = read_requests(capture["log_path"])

    assert len(requests) == 1
    request = requests[0]
    assert request["method"] == "POST"
    assert request["path"] == "/compat/e2b/v2/sandboxes"
    assert header_value(request["headers"], "X-API-KEY") == API_KEY
    assert header_value(request["headers"], "Idempotency-Key") == "trace-create-001"
    assert request["body"] == {
        "templateID": "trace-template",
        "timeout": 42,
        "metadata": {"purpose": "contract-capture", "run": "local"},
        "envVars": {"FOO": "bar", "EMPTY": ""},
    }

    assert sandbox.sandbox_id == "sbx_trace_001"
    assert sandbox.sandbox_domain == "sandbox.example.test"
    assert str(sandbox._envd_version) == "0.8.0"
    assert sandbox._envd_access_token == "envd-access-token"
    assert sandbox.traffic_access_token is None
    assert sandbox.envd_api_url == (
        "https://49983-sbx_trace_001.sandbox.example.test"
    )


def test_explicit_none_timeout_is_omitted(tmp_path: Path) -> None:
    with capture_at(tmp_path) as capture:
        create_sandbox(capture["url"], timeout=None)
        requests = read_requests(capture["log_path"])

    assert len(requests) == 1
    assert requests[0]["body"] == {
        "templateID": "base",
        "metadata": {},
        "envVars": {},
    }
    assert header_value(requests[0]["headers"], "Idempotency-Key") is None


def test_only_four_create_response_fields_are_required(tmp_path: Path) -> None:
    with capture_at(tmp_path, include_optional_response_fields=False) as capture:
        sandbox = create_sandbox(capture["url"])
        requests = read_requests(capture["log_path"])

    assert len(requests) == 1
    assert sandbox.sandbox_id == "sbx_trace_001"
    assert str(sandbox._envd_version) == "0.8.0"
    assert sandbox._envd_access_token is None
    assert sandbox.traffic_access_token is None


def test_delete_success_repeated_and_unknown(tmp_path: Path) -> None:
    with capture_at(tmp_path) as capture:
        base_url = capture["url"] + "/compat/e2b"
        sandbox = create_sandbox(base_url, template="trace-template")

        first = sandbox.kill()
        repeated = sandbox.kill()
        unknown = Sandbox.kill(
            "sbx_missing_404",
            api_key=API_KEY,
            api_url=base_url,
            http_version="1.1",
            retries=0,
        )
        requests = read_requests(capture["log_path"])

    assert (first, repeated, unknown) == (True, False, False)
    assert [(item["method"], item["path"]) for item in requests] == [
        ("POST", "/compat/e2b/v2/sandboxes"),
        ("DELETE", "/compat/e2b/sandboxes/sbx_trace_001"),
        ("DELETE", "/compat/e2b/sandboxes/sbx_trace_001"),
        ("DELETE", "/compat/e2b/sandboxes/sbx_missing_404"),
    ]
    assert [item["response_status"] for item in requests] == [201, 204, 404, 404]


def test_404_without_code_breaks_sdk_response_parsing(tmp_path: Path) -> None:
    with capture_at(tmp_path, valid_error_body=False) as capture:
        sandbox = create_sandbox(capture["url"])
        assert sandbox.kill() is True

        with pytest.raises(KeyError, match="code"):
            sandbox.kill()

        requests = read_requests(capture["log_path"])

    assert [item["response_status"] for item in requests] == [201, 204, 404]


def test_retryable_503_is_retried_once(tmp_path: Path) -> None:
    with capture_at(tmp_path, retry_failures=1) as capture:
        sandbox = Sandbox.create(
            api_key=API_KEY,
            api_url=capture["url"],
            http_version="1.1",
            retries=1,
        )
        requests = read_requests(capture["log_path"])

    assert sandbox.sandbox_id == "sbx_trace_001"
    assert [item["response_status"] for item in requests] == [503, 201]
    assert all(item["path"] == "/v2/sandboxes" for item in requests)


def test_request_timeout_raises_httpx_read_timeout(tmp_path: Path) -> None:
    with capture_at(tmp_path, delay=0.5) as capture:
        started = time.perf_counter()
        with pytest.raises(httpx.ReadTimeout):
            Sandbox.create(
                api_key=API_KEY,
                api_url=capture["url"],
                http_version="1.1",
                retries=0,
                request_timeout=0.15,
            )
        elapsed = time.perf_counter() - started

        time.sleep(0.55)
        requests = read_requests(capture["log_path"])

    assert elapsed < 0.45
    assert len(requests) == 1
    assert requests[0]["path"] == "/v2/sandboxes"
    assert requests[0]["body"]["templateID"] == "base"
