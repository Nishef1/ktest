# Experiment ledger

Definitions: **Passed** means local unit tests verified intended code behavior, not censorship circumvention. **Unverified** means no controlled field evidence; **Failed** must include reproducible observations. Keep sensitive measurements offline.

| Date (UTC) | ID | Environment | Method | Result | Notes |
| --- | --- | --- | --- | --- | --- |
| 2026-10-13 | LOCAL-001 | Go 1.23 loopback | HTTP Host override, bounded response, redirect handling | Passed | Self-hosted test server; no DPI |
| 2026-10-13 | LOCAL-002 | Go 1.23 loopback | TLS certificate validation (untrusted rejected; trusted accepted) | Passed | Self-hosted TLS server; no DPI |
| 2026-10-13 | FIELD-001 | Iranian ISP | Direct vs optional pinned destination | Unverified | Needs local run |
| 2026-10-13 | FIELD-002 | Iranian ISP | TLS SNI/HTTP Host combinations | Unverified | Only authorized destinations |
| 2026-10-13 | FIELD-003 | Iranian ISP | External packet desync tool vs direct baseline | Unverified | Needs design/security review |

| 2026-10-13 | LOCAL-003 | Go 1.23.2 local runner, before toolchain upgrade | A/B comparison generator, alternating trial order, summary and TLS pinning tests | Passed | No Iranian ISP measurements; no circumvention claim |

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

## Paired comparison — controlled endpoints only

Direct versus a pre-existing **local TCP forwarding tool**, started separately and with proper permissions:

```sh
go run ./cmd/ktest compare -authorized -url https://your-controlled-domain.example/ -connect 127.0.0.1:40443 -rounds 3
```

Controlled Host/SNI routing (certificate validation failures are recorded, **not bypassed**):

```sh
go run ./cmd/ktest compare -authorized -url https://your-controlled-domain.example/ -connect 203.0.113.10:443 -host front.example -sni front.example -rounds 3
```

The test includes an unmodified baseline and only those variants requested through flags. A verified 2xx/3xx response is not proof of domain-fronting, equivalence of page content, foreign IP egress or DPI evasion. 403 and 421 are classified as HTTP failures. Medians with three observations are descriptive, not statistically conclusive. Do not upload private field reports to this public repository.

## Stage P2: verifiable controlled-origin tests

The new proof mode requires the test server to echo the random challenge in its response header. It is not a VPN, CDN exploit, or universal proof that arbitrary services are reachable.

For a **loopback-only** trial:

```sh
ktest echo -listen 127.0.0.1:18080
ktest probe -url http://127.0.0.1:18080/__ktest/proof -proof
```

For a remote environment you **control**, bind `ktest echo` on loopback behind your own HTTPS reverse proxy; TLS certificate validation stays enabled. Run:

```sh
ktest compare -authorized -url https://YOUR-AUTHORIZED-DOMAIN/__ktest/proof -connect YOUR-AUTHORIZED-IP:443 -proof -rounds 3
```

If Host/SNI comparison is needed, pass `-host` and/or `-sni` for a domain you are explicitly authorized to test. This test sends at most 50 requests in ten five-variant rounds and emits summaries, not an automatic bypass claim. The challenge is a new 128-bit value for each request, never output or persisted.

A standard 2xx page without matching proof produces `proof_missing` or `proof_mismatch`. HTTP 301/302 are now `http_redirect` failures for reachability proof. `verified_origin` is reported separately from HTTP status. Even an apparently good candidate needs fresh real-ISP measurements; no such measurements were performed here.

| Date (UTC) | ID | Environment | Experiment | Result |
| --- | --- | --- | --- | --- |
| 2026-10-13 | LOCAL-004 | Go local httptest | Fresh nonce with trusted TLS, replay/missing proof, remote HTTP refusal | Passed |
| 2026-10-13 | LOCAL-005 | Go local httptest | Self-hosted proof echo, malformed challenge rejection | Passed |
| 2026-10-13 | LOCAL-006 | Unit runner | Candidate versus inconclusive, missing route, unverified baseline | Passed |
| 2026-10-13 | IRAN-004 | Real operator | Same experiments across fixed/mobile networks | Not conducted |
