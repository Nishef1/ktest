# Experiment ledger

Definitions: **Passed** means local unit tests verified intended code behavior, not censorship circumvention. **Unverified** means no controlled field evidence; **Failed** must include reproducible observations. Keep sensitive measurements offline.

| Date (UTC) | ID | Environment | Method | Result | Notes |
| --- | --- | --- | --- | --- | --- |
| 2026-10-13 | LOCAL-001 | Go 1.23 loopback | HTTP Host override, bounded response, redirect handling | Passed | Self-hosted test server; no DPI |
| 2026-10-13 | LOCAL-002 | Go 1.23 loopback | TLS certificate validation (untrusted rejected; trusted accepted) | Passed | Self-hosted TLS server; no DPI |
| 2026-10-13 | FIELD-001 | Iranian ISP | Direct vs optional pinned destination | Unverified | Needs local run |
| 2026-10-13 | FIELD-002 | Iranian ISP | TLS SNI/HTTP Host combinations | Unverified | Only authorized destinations |
| 2026-10-13 | FIELD-003 | Iranian ISP | External packet desync tool vs direct baseline | Unverified | Needs design/security review |

## Minimal invocation

```sh
go run ./cmd/ktest probe -url https://example.org/ -network tcp4 -repeat 2
```

Optional controlled routing (TLS certificate verification remains on):

```sh
go run ./cmd/ktest probe -url https://your-controlled-domain.example/ -connect 203.0.113.10:443 -sni your-controlled-domain.example -host your-controlled-domain.example
```

The documentation-only address above is from RFC 5737; replace it with your own test endpoint. Results are one JSON object per line. Exit status 0 means HTTP status 2xx/3xx, status 1 means the response or connection did not satisfy the criterion, status 2 means invalid arguments.

## Measurement template for future controlled testing

- Timestamp (UTC), anonymized network class (mobile/fixed, IPv4/IPv6), software commit SHA, target service controlled by researcher.
- Baseline and changed treatment measured on the same network within a short interval; 3-5 repeat tests per arm, low overall volume.
- DNS result, connection success, verified TLS certificate, HTTP status (notably 403/421), RTT/elapsed, body bytes read, visible redirects (disabled in tool).
- Report any unexpected root CA trust changes, instability, resets, leaked DNS/IPv6 paths separately.
- Outcomes: `verified`, `rejected`, `inconclusive`; NEVER infer worldwide or month-long reliability from one success.
