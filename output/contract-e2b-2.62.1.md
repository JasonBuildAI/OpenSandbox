# Python SDK contract trace: create -> delete (`e2b==2.62.1`)

## Scope and evidence

- SDK: synchronous Python `e2b==2.62.1`, source commit `9301cd84757b0e3f3fccbd349e85ff2bd403a1f4`.
- Runtime used for this trace: Python 3.13.18, HTTP/1.1, `retries=0` unless a case says otherwise.
- Backend: a local recording stub on `127.0.0.1`. No Docker, KVM, Fast Sandbox, or real envd was used.
- Scope: create -> delete only. This does not cover command/file traffic or real-backend acceptance.
- Evidence labels: **measured** = observed on the local stub; **source-read** = read from the pinned SDK source; **not verified** = needs a real Fast Sandbox tuple.

This is contract-development evidence, not Gate 1a acceptance and not a claim of E2B compatibility.

## Results at a glance

| Case | What the SDK sent | What the SDK did with the response | Evidence |
| --- | --- | --- | --- |
| Create with defaults | `POST /v2/sandboxes`; `x-api-key`; body `{"templateID":"base","metadata":{},"envVars":{}}` | Returned a sandbox object from `201` | measured |
| Create with explicit fields | `POST /compat/e2b/v2/sandboxes`; body included `templateID`, `timeout`, `metadata`, `envVars` | Returned a sandbox object from `201` | measured |
| Create, one retry | First request got `503` + `Should-Retry: true` with an explicit idempotency key; SDK repeated the identical `POST` and accepted the second `201` | Returned a sandbox object after two requests | measured |
| Create, retry suppressed | `503` + `Should-Retry: false` | Sent one request and raised `ServiceBusyException` | measured |
| Create, non-transient status retried | `400` + `Should-Retry: true` | Sent two requests and returned the sandbox from the second `201` | measured |
| Create, request timeout | One `POST`; stub delayed its response | Raised `httpx.ReadTimeout` after about 0.31 s | measured |
| Create, trailing-slash base | Base URL ended in `/compat/e2b/` | Request path normalized to `/compat/e2b/v2/sandboxes`; no double slash | measured |
| Delete success | `DELETE /compat/e2b/sandboxes/{id}`, no body; `204` | Returned `True` | measured |
| Delete again / unknown ID | Same `DELETE`; `404` with `{"code":404,"message":"Sandbox not found"}` | Returned `False` | measured |
| Delete with malformed 404 | Same `DELETE`; `404` with only `{"message":"Sandbox not found"}` | Raised `KeyError: 'code'`; did not return `False` | measured |

## Create request

The base URL is path-scoped to the proposed adapter mount. A base URL of `http://127.0.0.1:<port>/compat/e2b` produced:

```http
POST /compat/e2b/v2/sandboxes
x-api-key: e2b_test_key
content-type: application/json
user-agent: e2b-python-sdk/2.62.1
idempotency-key: trace-create-001   # only when idempotency_key is explicitly passed
```

A base URL ending in `/compat/e2b/` also produced `/compat/e2b/v2/sandboxes`; the SDK normalized the join and did not create a double slash. This is measured and covers the trailing-slash configuration called out by OSEP T1.

The measured request body for explicit fields was:

```json
{
  "templateID": "trace-template",
  "timeout": 42,
  "metadata": {
    "purpose": "contract-capture",
    "run": "local"
  },
  "envVars": {
    "FOO": "bar",
    "EMPTY": ""
  }
}
```

Observed mapping: Python `template` -> `templateID`; `envs` -> `envVars`. The SDK also sends `metadata: {}` and `envVars: {}` when the caller omits them.

The minimal measured body was:

```json
{
  "templateID": "base",
  "metadata": {},
  "envVars": {}
}
```

There was no `timeout` key when the caller passed `timeout=None` or omitted it. There was also no `Idempotency-Key` header unless `idempotency_key` was passed explicitly. The SDK source validates an explicit idempotency key as 1-255 lowercase ASCII letters, digits, or hyphens before sending it.

## Create response

The SDK's generated response parser accepts `201` for a successful create. The following response was accepted:

```http
HTTP/1.1 201 Created
Content-Type: application/json
```

```json
{
  "templateID": "base",
  "sandboxID": "sbx_trace_001",
  "clientID": "client_trace",
  "envdVersion": "0.8.0",
  "envdAccessToken": "envd-access-token",
  "trafficAccessToken": null,
  "domain": "sandbox.example.test"
}
```

The four fields required by the SDK response model are `templateID`, `sandboxID`, `clientID`, and `envdVersion`. I verified that a response containing only those four fields is enough to construct the SDK object. `clientID` is required by the parser even though the high-level `Sandbox` object does not expose it.

`201` is the only successful create status recognized by the generated parser. A `200` response would leave the parsed body as `None`; the high-level create path then raises `Exception("Body of the request is None")`. Adapter implication: return `201` for create. This is source-read, not a stub measurement.

`alias`, `envdAccessToken`, `trafficAccessToken`, and `domain` are optional for parsing. However, `domain` is not operationally optional for routing. With `domain` absent, the SDK fell back to its default domain `e2b.app` and produced the data-plane URL `https://sandbox.e2b.app`. An adapter should therefore return a usable `domain`, or the test profile must override the data-plane URL with `E2B_SANDBOX_URL` / `sandbox_url`.

`envdAccessToken` is also operationally important even though parsing is optional. Source-read: when present as a string, the SDK adds it as `X-Access-Token` on envd requests. A Gate 1a data-plane test with a token-protected envd should return it; otherwise the SDK will not send that header.

With the example response above, the SDK produced this data-plane URL:

```text
https://49983-sbx_trace_001.sandbox.example.test
```

This matches the source-read rules: envd port `49983`; the normal host form is `{port}-{sandboxID}.{domain}`; for domains the SDK treats as first-party it uses `https://sandbox.<domain>` instead; and `E2B_SANDBOX_URL` / `sandbox_url` overrides both forms.

There is one hard version gate after parsing: source-read `_create_sandbox` compares `envdVersion` with `0.1.0`. If the returned version is lower, the SDK first kills the newly created sandbox and then raises `TemplateException`. An adapter should never return an envd version below `0.1.0`.

## Delete request and status mapping

With the path-scoped base URL, the SDK sent:

```http
DELETE /compat/e2b/sandboxes/sbx_trace_001
x-api-key: e2b_test_key
```

There was no request body.

Measured mapping:

- `204` -> `True`.
- `404` with a valid error envelope -> `False`.
- A `404` whose body omitted `code` -> `KeyError: 'code'` before the high-level method could return `False`.
- Other non-2xx mappings were not traced against the stub; source says statuses at or above 300 go through the SDK's API-exception handler.

The generated 404 parser requires the standard error model:

```json
{
  "code": 404,
  "message": "Sandbox not found"
}
```

The generated model declares `code` as `int` and `message` as `str`. The parser itself does not perform an explicit runtime type check; the measured hard failure was the absence of the `code` key. A body with only `message` is not sufficient for the 404 path.

Source-read: the generated create route declares exactly these error statuses and parses each as this model: `400`, `401`, `403`, `404`, `409`, `422`, `429`, `500`, `503`, and `504`. Adapter implication: use `{code, message}` for those declared error responses rather than inventing a one-off shape.

## Timeout behavior

There are two different timeouts:

1. Sandbox TTL: the `timeout` request field. `timeout=42` appeared on the wire. `timeout=None` was omitted entirely; the SDK never serialized JSON `null`.
2. Control-plane request timeout: `request_timeout`. With a local response delay of 0.5 s and `request_timeout=0.15`, one request was sent and the SDK raised `httpx.ReadTimeout` in about 0.31 s. It did not retry in this case (`retries=0`).

Source-read defaults: control-plane request timeout is 60 s, and an omitted sandbox TTL is documented/modeled as 300 s. The local stub did not enforce either service-side value. The real service's default and maximum still need to be recorded on the selected deployment.

## Retry and transport settings

- `retries=1` produced exactly two attempts: `503` with `Should-Retry: true`, then `201`. The fixture now records the response header, path, body, and the explicit `Idempotency-Key`; both attempts carried the same key.
- `503` with `Should-Retry: false` produced exactly one attempt and raised `ServiceBusyException`; the `false` header overrides the normally retryable status.
- `400` with `Should-Retry: true` produced two attempts and returned the second successful `201`. This confirms the explicit header can make a non-transient status retryable.
- Source-read default is three retries, meaning up to four attempts total. The retry layer covers responses marked `Should-Retry: true`, plus `429`, `502`, `503`, and `504` when that header is absent.
- Source-read: a valid `Retry-After` delta-seconds value is used for the wait; otherwise the SDK uses bounded exponential backoff with jitter.
- Connection retries are separate and controlled by `E2B_CONNECTION_RETRIES`; the source-read default is three. For deterministic contract tests, set both the SDK `retries` option and `E2B_CONNECTION_RETRIES` to zero.
- Source-read default HTTP version is `2`; this trace explicitly used `1.1`. The recommended test profile should also pin `E2B_HTTP_VERSION=1.1`.
- `api_url` / `E2B_API_URL` and `sandbox_url` / `E2B_SANDBOX_URL` are deprecated control hooks, but they are what make the path-scoped local adapter and fake envd routing possible in `2.62.1`.

One observed retry caveat: when `idempotency_key` is omitted, the retried create request carries no idempotency key. The adapter's duplicate-create behavior for an already accepted request is therefore still an open contract question.

## Adapter implications

1. Return `201` for create, with at least `templateID`, `sandboxID`, `clientID`, and `envdVersion` as strings.
2. Return a usable `domain` that resolves the data plane, or explicitly document that tests must override it with `E2B_SANDBOX_URL` / `sandbox_url`.
3. Return `envdAccessToken` when the target envd requires it; otherwise the SDK will omit `X-Access-Token` on data-plane requests.
4. Use `{code, message}` for exactly the error statuses declared by the generated create route, and make sure `code` is present. The 404 parser hard-fails when it is absent.
5. Never return an `envdVersion` below `0.1.0`; the SDK kills the new sandbox and raises `TemplateException` first.

## Source anchors

- [Create entry point](https://github.com/e2b-dev/E2B/blob/9301cd84757b0e3f3fccbd349e85ff2bd403a1f4/packages/python-sdk/e2b/sandbox_sync/main.py#L167) and [kill entry point](https://github.com/e2b-dev/E2B/blob/9301cd84757b0e3f3fccbd349e85ff2bd403a1f4/packages/python-sdk/e2b/sandbox_sync/main.py#L545).
- [Low-level create](https://github.com/e2b-dev/E2B/blob/9301cd84757b0e3f3fccbd349e85ff2bd403a1f4/packages/python-sdk/e2b/sandbox_sync/sandbox_api.py#L211) and [kill](https://github.com/e2b-dev/E2B/blob/9301cd84757b0e3f3fccbd349e85ff2bd403a1f4/packages/python-sdk/e2b/sandbox_sync/sandbox_api.py#L137).
- [Create route](https://github.com/e2b-dev/E2B/blob/9301cd84757b0e3f3fccbd349e85ff2bd403a1f4/packages/python-sdk/e2b/api/client/api/sandboxes/post_v2_sandboxes.py#L39): `POST /v2/sandboxes`, success at `201`; [delete route](https://github.com/e2b-dev/E2B/blob/9301cd84757b0e3f3fccbd349e85ff2bd403a1f4/packages/python-sdk/e2b/api/client/api/sandboxes/delete_sandboxes_sandbox_id.py#L16): `DELETE /sandboxes/{sandbox_id}`.
- [Create response model](https://github.com/e2b-dev/E2B/blob/9301cd84757b0e3f3fccbd349e85ff2bd403a1f4/packages/python-sdk/e2b/api/client/models/sandbox.py#L26): four required fields; [error model](https://github.com/e2b-dev/E2B/blob/9301cd84757b0e3f3fccbd349e85ff2bd403a1f4/packages/python-sdk/e2b/api/client/models/error.py#L26): required `code` and `message`.
- [Transport defaults](https://github.com/e2b-dev/E2B/blob/9301cd84757b0e3f3fccbd349e85ff2bd403a1f4/packages/python-sdk/e2b/connection_config.py#L32): request timeout, retries, HTTP version, envd port, and default domain.

## Open questions / not verified

- A real Fast Sandbox returning these exact statuses, headers, and JSON bodies.
- The real service's accepted `timeout` range, default, maximum, and its `400` body for an invalid value.
- How the adapter should represent duplicate creates, especially when the request has no `Idempotency-Key`.
- The real `400` / `409` / `503` error envelopes and their `error_code` values.
- What semantic value the adapter should use for the parser-required `clientID` field: a fixed adapter identity, a scope-derived client, or another stable identifier.
- Which `domain` the adapter will return, and whether the test profile will instead rely on `E2B_SANDBOX_URL`.
- Command and file traffic. Those were deliberately not traced here because this contribution was scoped to create/delete first.

## Reproduction artifacts

- `samples/fixtures/*.json`: per-case request/response fixtures with measured SDK observations.
- `samples/raw/*.jsonl`: raw recorder logs from the local stub.
- `tests/test_e2b_contract.py`: ten runnable contract tests.
- `trace_e2b.py`: regenerates every fixture.
- `capture_server.py`: local recording stub.

Local verification: ten tests pass with `python -m pytest tests -q` against `e2b==2.62.1`.
