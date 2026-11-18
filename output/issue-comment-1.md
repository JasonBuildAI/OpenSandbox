I traced the create -> delete step for the Python SDK row, pinned to `e2b==2.62.1` ([SDK source commit `9301cd8`](https://github.com/e2b-dev/E2B/tree/9301cd84757b0e3f3fccbd349e85ff2bd403a1f4)). This is local-stub evidence, not compatibility acceptance and not a Gate 1a result.

**Measured**

1. Create is `POST /compat/e2b/v2/sandboxes` when the base URL is `/compat/e2b`, with `x-api-key`. The minimal body is `{"templateID":"base","metadata":{},"envVars":{}}`; Python `envs` maps to `envVars`. `timeout=None` is omitted (no JSON `null`), while `timeout=42` is sent. A trailing-slash base (`/compat/e2b/`) is normalized and does not produce a double slash.
2. The create response needs `templateID`, `sandboxID`, `clientID`, and `envdVersion`. `domain` and `envdAccessToken` are optional to parse but operationally important: without `domain` the SDK falls back to `https://sandbox.e2b.app` (measured); without `envdAccessToken` it will not send `X-Access-Token` to envd (source-read).
3. Retry behavior is header-driven: `503 + Should-Retry: true` with `retries=1` produced two identical POSTs and the same explicit `Idempotency-Key`; `503 + Should-Retry: false` produced one request then `ServiceBusyException`; `400 + Should-Retry: true` also retried once. Response headers are recorded in the fixtures.
4. Delete is `DELETE /compat/e2b/sandboxes/{id}` with no body. `204` returns `True`; `404` returns `False`; a `404` with only `message` raises `KeyError: 'code'`. The error envelope must include both `code` and `message`.
5. With a delayed stub and `request_timeout=0.15`, one request was sent and the SDK raised `httpx.ReadTimeout` rather than an E2B `TimeoutException`.

**Adapter implications**

- Return `201` with the four required fields. A `200` response is not a successful create for the generated parser. Return `envdVersion >= 0.1.0`; below that, the SDK kills the new sandbox and raises `TemplateException` (source-read).
- Return a usable `domain`, and return `envdAccessToken` when the target envd requires it.
- Use `{code, message}` for exactly the error statuses declared by the generated create route: `400`, `401`, `403`, `404`, `409`, `422`, `429`, `500`, `503`, and `504` (source-read; the 404 behavior is measured).

**Not verified**

Real Fast Sandbox acceptance, the service-side timeout range/default, real `400` / `409` / `503` envelopes, the intended semantic for parser-required `clientID`, and command/file traffic remain open. The tested round trip here is create -> delete only.

Full report: https://gist.github.com/JasonBuildAI/a6c04766b1b7fd7eda74d4c4010c6d54  
Fork branch and artifacts: https://github.com/JasonBuildAI/OpenSandbox/tree/e311c822f70acc98719c747b279b56ab723cfcc3  
Tests: https://github.com/JasonBuildAI/OpenSandbox/blob/e311c822f70acc98719c747b279b56ab723cfcc3/tests/test_e2b_contract.py (10 pass locally)  
Fixtures: https://github.com/JasonBuildAI/OpenSandbox/tree/e311c822f70acc98719c747b279b56ab723cfcc3/samples/fixtures
