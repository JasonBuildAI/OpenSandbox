"""Pinned `e2b==2.62.1` command (envd process) contract, measured against a local stub.

Development evidence only: a stub is not Fast Sandbox compatibility acceptance.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest
from e2b import CommandExitException, Sandbox, TimeoutException

from capture_server import start_capture_server, stop_capture_server

API_KEY = "e2b_test_key"
START = "/process.Process/Start"


@contextmanager
def capture_at(tmp_path: Path, **server_options: Any) -> Iterator[dict[str, Any]]:
    log_path = tmp_path / "capture.jsonl"
    server, thread, root_url = start_capture_server(log_path, **server_options)
    try:
        yield {"url": root_url, "log_path": log_path}
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
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def start_request(requests: list[dict[str, Any]]) -> dict[str, Any]:
    starts = [item for item in requests if item["path"] == START]
    assert len(starts) == 1
    return starts[0]


def test_command_run_request_and_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with capture_at(tmp_path, command_mode="echo") as capture:
        monkeypatch.setenv("E2B_SANDBOX_URL", capture["url"])
        sandbox = create_sandbox(capture["url"])
        result = sandbox.commands.run("echo hello")
        requests = read_requests(capture["log_path"])

    assert result.stdout == "hello\n"
    assert result.stderr == ""
    assert result.exit_code == 0

    request = start_request(requests)
    headers = request["headers"]
    assert header_value(headers, "Content-Type") == "application/connect+json"
    assert header_value(headers, "Connect-Protocol-Version") == "1"
    assert header_value(headers, "Connect-Timeout-Ms") == "60000"
    assert header_value(headers, "X-Access-Token") == "envd-access-token"
    assert header_value(headers, "E2b-Sandbox-Id") == "sbx_trace_001"
    assert header_value(headers, "E2b-Sandbox-Port") == "49983"

    message = request["body"]["frames"][0]["json"]
    assert message["process"] == {
        "cmd": "/bin/bash",
        "args": ["-l", "-c", "echo hello"],
    }
    assert message["stdin"] is False

    events = [item["event"] for item in request["rpc_events"]]
    assert events[0]["start"]["pid"] == 4242
    assert [event["data"]["stdout"] for event in events if "data" in event] == [
        "aGVsbG8K"
    ]
    assert events[-1]["end"]["exited"] is True


def test_command_nonzero_exit_raises_command_exit_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with capture_at(tmp_path, command_mode="exit1") as capture:
        monkeypatch.setenv("E2B_SANDBOX_URL", capture["url"])
        sandbox = create_sandbox(capture["url"])
        with pytest.raises(CommandExitException) as info:
            sandbox.commands.run("exit 1")
        requests = read_requests(capture["log_path"])

    assert info.value.exit_code == 1
    assert info.value.stderr == "boom\n"
    assert info.value.stdout == ""

    request = start_request(requests)
    end = [item["event"] for item in request["rpc_events"]][-1]["end"]
    assert end["exitCode"] == 1


def test_command_background_streams_chunks_to_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with capture_at(tmp_path, command_mode="chunks") as capture:
        monkeypatch.setenv("E2B_SANDBOX_URL", capture["url"])
        sandbox = create_sandbox(capture["url"])
        callbacks: list[str] = []
        handle = sandbox.commands.run("echo hello", background=True)
        result = handle.wait(on_stdout=callbacks.append)
        requests = read_requests(capture["log_path"])

    assert callbacks == ["hel", "lo\n"]
    assert result.stdout == "hello\n"
    assert result.exit_code == 0
    start_request(requests)


def test_command_stdin_uses_send_input_and_close_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with capture_at(tmp_path, command_mode="stdin") as capture:
        monkeypatch.setenv("E2B_SANDBOX_URL", capture["url"])
        sandbox = create_sandbox(capture["url"])
        handle = sandbox.commands.run("cat", background=True, stdin=True)
        handle.send_stdin("hi\n")
        handle.close_stdin()
        result = handle.wait()
        requests = read_requests(capture["log_path"])

    assert result.stdout == "hi\n"
    assert result.exit_code == 0

    by_path = {item["path"]: item for item in requests}
    input_request = by_path["/process.Process/SendInput"]
    assert header_value(input_request["headers"], "Content-Type") == "application/json"
    assert header_value(input_request["headers"], "E2b-Sandbox-Id") == "sbx_trace_001"
    assert header_value(input_request["headers"], "X-Access-Token") == (
        "envd-access-token"
    )
    assert input_request["body"]["messages"][0]["input"] == {"stdin": "aGkK"}
    assert input_request["body"]["messages"][0]["decoded_stdin"] == "hi\n"

    close_request = by_path["/process.Process/CloseStdin"]
    assert close_request["body"]["messages"][0]["process"] == {"pid": 4242}


def test_command_timeout_is_a_connect_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with capture_at(tmp_path, command_mode="hang") as capture:
        monkeypatch.setenv("E2B_SANDBOX_URL", capture["url"])
        sandbox = create_sandbox(capture["url"])
        with pytest.raises(TimeoutException):
            sandbox.commands.run("sleep 5", timeout=1)
        requests = read_requests(capture["log_path"])

    request = start_request(requests)
    assert header_value(request["headers"], "Connect-Timeout-Ms") == "1000"
    assert len(request["rpc_events"]) == 1
    assert "start" in request["rpc_events"][0]["event"]
