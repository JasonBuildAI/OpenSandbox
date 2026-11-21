# E2B 2.62.1 create/delete and command contract trace

This directory contains local, reproducible evidence for the Python SDK
create/delete lifecycle and the envd command round trip. It does not implement
or validate E2B compatibility.

The recorded environment is Python 3.13.18 on Windows. The SDK's connection
retry count is read when `e2b` is imported, so the runner scripts set
`E2B_CONNECTION_RETRIES=0` before importing it. `pytest` does the same in
`tests/conftest.py`.

## Reproduce

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe trace_e2b.py
.\.venv\Scripts\python.exe -m pytest tests -q
```

`trace_e2b.py` regenerates `samples/raw/*.jsonl`, `samples/fixtures/*.json`, and
`output/capture-summary.json` from a local recording stub.

## Main artifacts

- `output/contract-e2b-2.62.1.md`: issue-ready review report.
- `tests/test_e2b_contract.py`: ten lifecycle contract tests.
- `tests/test_e2b_command_contract.py`: five command contract tests.
- `capture_server.py`: local control-plane and envd command stub.
- `samples/fixtures/`: request/response pairs with SDK observations.

## Command coverage

`command_mode` on the stub plays one of `echo`, `exit1`, `chunks`, `stdin`,
`hang`. The SDK is pointed at the stub with `E2B_SANDBOX_URL`. Measured on
`e2b==2.62.1`: commands do not use a REST route. `commands.run` sends
`POST /process.Process/Start` over HTTP/1.1 with `Content-Type:
application/connect+json` (Connect streaming frames), `connect-timeout-ms` set
from the command `timeout`, and `X-Access-Token`, `E2b-Sandbox-Id`,
`E2b-Sandbox-Port` headers. Stdin uses unary `POST /process.Process/SendInput`
and `CloseStdin` with plain `application/json`.

All request and response evidence is measured against the local stub only.
Real envd, router forwarding, and Fast Sandbox acceptance remain out of scope.
