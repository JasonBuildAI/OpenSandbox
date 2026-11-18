# E2B 2.62.1 create/delete contract trace

This directory contains local, reproducible evidence for the Python SDK create
and delete contract. It does not implement or validate E2B compatibility.

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
- `tests/test_e2b_contract.py`: ten runnable contract tests.
- `capture_server.py`: local control-plane stub.
- `samples/fixtures/`: request/response pairs with SDK observations.

All request and response evidence is measured against the local stub only.
Real Fast Sandbox acceptance remains out of scope.
