Full audit trail for the create -> delete trace:

- Report: https://gist.github.com/JasonBuildAI/a6c04766b1b7fd7eda74d4c4010c6d54
- Commit: https://github.com/JasonBuildAI/OpenSandbox/commit/e311c822f70acc98719c747b279b56ab723cfcc3
- Reproducer and recorder: https://github.com/JasonBuildAI/OpenSandbox/tree/e311c822f70acc98719c747b279b56ab723cfcc3
- Fixtures: https://github.com/JasonBuildAI/OpenSandbox/tree/e311c822f70acc98719c747b279b56ab723cfcc3/samples/fixtures
- Tests: https://github.com/JasonBuildAI/OpenSandbox/blob/e311c822f70acc98719c747b279b56ab723cfcc3/tests/test_e2b_contract.py

The raw JSONL and per-case fixtures include response headers, so the retry cases are directly auditable. All results are against the local stub; none is a real Fast Sandbox or Gate 1a claim.
