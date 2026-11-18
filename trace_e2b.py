"""Capture the pinned E2B Python SDK's create/delete control-plane traffic.

This is contract-development evidence, not Gate 1a acceptance. It talks only to
a local stub and does not prove that a real Fast Sandbox accepts these requests.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from capture_server import start_capture_server, stop_capture_server

os.environ.setdefault("E2B_CONNECTION_RETRIES", "0")

from e2b import Sandbox  # noqa: E402 - env must be set before importing the SDK


ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / "samples"
RAW = SAMPLES / "raw"
FIXTURES = SAMPLES / "fixtures"
OUTPUT = ROOT / "output"
SDK_VERSION = "2.62.1"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _sandbox_view(sandbox: Sandbox) -> dict[str, Any]:
    return {
        "sandbox_id": sandbox.sandbox_id,
        "sandbox_domain": sandbox.sandbox_domain,
        "envd_version": str(sandbox._envd_version),
        "envd_access_token": sandbox._envd_access_token,
        "traffic_access_token": sandbox.traffic_access_token,
        "envd_api_url": sandbox.envd_api_url,
    }


def _sdk_create(base_url: str, **kwargs: Any) -> Sandbox:
    return Sandbox.create(
        api_key="e2b_test_key",
        api_url=base_url,
        http_version="1.1",
        retries=0,
        **kwargs,
    )


def _run_case(
    name: str,
    action: Callable[[str], Any],
    *,
    base_path: str = "",
    retry_failures: int = 0,
    delay: float = 0.0,
    valid_error_body: bool = True,
    include_optional_response_fields: bool = True,
    failure_status: int = 503,
    failure_retry_header: str | None = "true",
) -> dict[str, Any]:
    log_path = RAW / f"{name}.jsonl"
    server, thread, root_url = start_capture_server(
        log_path,
        retry_failures=retry_failures,
        delay=delay,
        valid_error_body=valid_error_body,
        include_optional_response_fields=include_optional_response_fields,
        failure_status=failure_status,
        failure_retry_header=failure_retry_header,
    )
    api_url = root_url + base_path
    started = time.perf_counter()
    result: dict[str, Any] = {
        "scenario": name,
        "sdk_version": SDK_VERSION,
        "api_url": api_url,
        "evidence": "measured",
    }

    try:
        value = action(api_url)
        result["ok"] = True
        result["sdk_result"] = value
    except Exception as exc:  # noqa: BLE001 - the exception is the observation
        result["ok"] = False
        result["exception"] = {
            "type": type(exc).__name__,
            "module": type(exc).__module__,
            "message": str(exc),
        }
    finally:
        result["elapsed_seconds"] = round(time.perf_counter() - started, 4)
        if delay:
            time.sleep(delay + 0.15)
        stop_capture_server(server, thread)

    records = _read_jsonl(log_path)
    result["request_count"] = len(records)
    result["transactions"] = [
        {
            "request": {
                "method": record["method"],
                "path": record["path"],
                "headers": record["headers"],
                "body": record["body"],
            },
            "response": {
                "status": record["response_status"],
                "headers": record.get("response_headers", {}),
                "body": record["response_body"],
            },
        }
        for record in records
    ]
    return result


def capture() -> list[dict[str, Any]]:
    RAW.mkdir(parents=True, exist_ok=True)
    FIXTURES.mkdir(parents=True, exist_ok=True)
    OUTPUT.mkdir(parents=True, exist_ok=True)

    cases: list[dict[str, Any]] = []

    cases.append(
        _run_case(
            "create_minimal",
            lambda base: _sandbox_view(_sdk_create(base, timeout=None)),
        )
    )

    cases.append(
        _run_case(
            "create_explicit_fields_compat_base",
            lambda base: _sandbox_view(
                _sdk_create(
                    base,
                    template="trace-template",
                    timeout=42,
                    metadata={"purpose": "contract-capture", "run": "local"},
                    envs={"FOO": "bar", "EMPTY": ""},
                    idempotency_key="trace-create-001",
                )
            ),
            base_path="/compat/e2b",
        )
    )

    cases.append(
        _run_case(
            "create_retry_once",
            lambda base: _sandbox_view(
                Sandbox.create(
                    api_key="e2b_test_key",
                    api_url=base,
                    http_version="1.1",
                    retries=1,
                    idempotency_key="trace-retry-001",
                )
            ),
            retry_failures=1,
        )
    )

    cases.append(
        _run_case(
            "create_retry_suppressed_by_header",
            lambda base: _sandbox_view(
                Sandbox.create(
                    api_key="e2b_test_key",
                    api_url=base,
                    http_version="1.1",
                    retries=1,
                )
            ),
            retry_failures=1,
            failure_retry_header="false",
        )
    )

    cases.append(
        _run_case(
            "create_retry_on_400",
            lambda base: _sandbox_view(
                Sandbox.create(
                    api_key="e2b_test_key",
                    api_url=base,
                    http_version="1.1",
                    retries=1,
                )
            ),
            retry_failures=1,
            failure_status=400,
            failure_retry_header="true",
        )
    )

    cases.append(
        _run_case(
            "create_request_timeout",
            lambda base: _sandbox_view(
                Sandbox.create(
                    api_key="e2b_test_key",
                    api_url=base,
                    http_version="1.1",
                    retries=0,
                    request_timeout=0.15,
                )
            ),
            delay=0.6,
        )
    )

    cases.append(
        _run_case(
            "create_required_response_fields_only",
            lambda base: _sandbox_view(_sdk_create(base)),
            include_optional_response_fields=False,
        )
    )

    cases.append(
        _run_case(
            "create_trailing_slash_base",
            lambda base: _sandbox_view(_sdk_create(base)),
            base_path="/compat/e2b/",
        )
    )

    def delete_flow(base: str) -> dict[str, Any]:
        sandbox = _sdk_create(base, template="trace-template")
        first = sandbox.kill()
        repeated = sandbox.kill()
        unknown = Sandbox.kill(
            "sbx_missing_404",
            api_key="e2b_test_key",
            api_url=base,
            http_version="1.1",
            retries=0,
        )
        return {
            "sandbox": _sandbox_view(sandbox),
            "first_kill": first,
            "repeated_kill": repeated,
            "unknown_kill": unknown,
        }

    cases.append(_run_case("delete_flow_compat_base", delete_flow, base_path="/compat/e2b"))

    def malformed_404_flow(base: str) -> dict[str, Any]:
        sandbox = _sdk_create(base)
        sandbox.kill()
        return {"repeated_kill": sandbox.kill()}

    cases.append(
        _run_case(
            "delete_404_without_code",
            malformed_404_flow,
            valid_error_body=False,
        )
    )

    for case in cases:
        (FIXTURES / f"{case['scenario']}.json").write_text(
            json.dumps(case, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    summary = {
        "sdk_version": SDK_VERSION,
        "evidence_note": (
            "All request/response fields below were measured against a local stub. "
            "They are not proof of real Fast Sandbox acceptance."
        ),
        "cases": cases,
    }
    (OUTPUT / "capture-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return cases


if __name__ == "__main__":
    for case in capture():
        print(
            f"{case['scenario']}: ok={case['ok']} "
            f"requests={case['request_count']} "
            f"elapsed={case['elapsed_seconds']}s"
        )
