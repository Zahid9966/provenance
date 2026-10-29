# Security model

| Threat | Control | Verified by |
|---|---|---|
| Credential stuffing / brute force | scrypt hashes; per-IP login rate limit; account lockout (5 fails/15 min); equal work for unknown users | `test_lockout…`, `test_login_rate_limit…` |
| Stolen password | Optional TOTP MFA (RFC 6238); codes are single-use | RFC vectors, replay test |
| Session theft / stale access | HMAC-signed 1 h tokens; server-side revocation (logout, password change) | `test_password_change_revokes…` |
| Privilege abuse | Deny-by-default RBAC, 5 roles; denials audited | RBAC tests |
| Insider fraud | Write-off requires a second, authorised person; refund/export/velocity detectors | SoD tests, detector tests |
| Audit tampering | HMAC hash chain **plus** signed external anchors → detects edit, delete, reorder, insert and tail truncation | chain + anchor tests |
| Data exfiltration | PII tokenised; per-role masking; copilot has no row-level access; SIEM export | masking tests |
| Prompt injection / data poisoning | Input scored and blocked; poisoned free text excluded from AI context; LLM output re-validated | copilot tests |
| Malicious upload | strict name allow-list, size cap, UTF-8/format checks, never overwrites evidence, parsed as data only | upload tests |
| XSS | UI uses `textContent` only; CSP `default-src 'none'`, no inline script | header test |
| Path traversal | resolved-path containment for static files | smoke test |

**Deployment hardening checklist**
- Keep `data/keys.json` and the audit-anchor location (`PROVENANCE_ANCHOR_DIR`) under separate control; use a WORM / object-lock volume for anchors.
- Terminate TLS in front of the app (compose `tls` profile) and set `PROVENANCE_HSTS=1`; use `sslmode=verify-full` for database connections.
- Rotate keys on a schedule and store them in your KMS/secret manager (the key file is created mode 0600).
- Run behind your identity-aware proxy for SSO; the app's own login supports MFA, lockout and revocable sessions.
