# Single-use TOTP atomic consumption review

Post-session AI-assisted independent review. Python3.14.3 with stdlib SQLite; exact dependency-lock and frozen imports retained. In totp-consumption-r1 use matching frozen src and verifier directory on PYTHONPATH; python -B -m pytest -q -s test_totp_consumption_review.py =>20 pass2 fail, both same unactivated-higher-generation issue. Independent HMAC oracle creates epoch0 and true short-code collision. Gated commit with2 actual independent SQLite connections proves uncommitted value invisible, concurrent loser never succeeds, committed value replays. Model replay tests40 pass. Existing core27 pass1 Windows before-epoch OSError; exact initial git archive separately reproduces27 pass1 same error, excluded from scoring. Original/final core normalized contents identical, raw byte SHA differ due CRLF-to-LF only; both recorded. No test statistics summed. Store only state not secret; no external database/service/container. Recorded demo runs fresh local DB, exposes real generation auto-replacement and exits1; openly automated75s capture.

No edits to frozen model source or original trajectory. User review required; no automatic submission.


冻结产物提交：https://github.com/9873199/totp-single-use-redemption/commit/95d9f199c324a30dadaf53741c1a12239b4e8b07
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
