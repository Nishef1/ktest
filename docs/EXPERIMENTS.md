# Experiment ledger

Definitions: **Passed** means local unit tests verified intended code behavior, not censorship circumvention. **Unverified** means no controlled field evidence; **Failed** must include reproducible observations. Keep sensitive measurements offline.

## Current code/CI status (2026-10-21)

The reviewed source snapshot was [`978e0ab`](https://github.com/Nishef1/ktest/commit/978e0ab487e086ed5da61478f313db60bf272365). At that snapshot, the verification workflow passed Ubuntu and Windows Go tests, formatting, race tests and Android source checks; the Android APK and Windows portable build workflows also passed:

- [Verify](https://github.com/Nishef1/ktest/actions/runs/39603654030)
- [Android APK build](https://github.com/Nishef1/ktest/actions/runs/39603653990)
- [Windows portable build](https://github.com/Nishef1/ktest/actions/runs/39603653941)

These are code/build checks, not field experiments. The current commit has not been comprehensively accepted on a physical Android phone or every target ISP. CPU, RAM, battery, cold/warm startup P50/P95, 20-cycle reconnect and sustained data-plane benchmarks are **not measured**. Historical emulator/ISP observations elsewhere in this repository must retain their original date and scope.

### ECH DNS update (2026-10-21)

A user report says UDP DNS queries for HTTPS records used to obtain Cloudflare ECHConfig were filtered on one network, while AliDNS DoH worked. This does not establish a nationwide ECH block. KTest already has a DNS-independent TCP/443 ECH retry-config bootstrap; a permanent hardcoded ECH key is not used. The packet DNS resolver now includes RFC 8484 AliDNS endpoints pinned to `223.5.5.5` and `223.6.6.6`, validating the certificate for `dns.alidns.com`. Unit coverage checks the endpoint configuration only. Physical-device tests must still confirm HTTPS/SVCB record resolution, TLS reachability, current ECH acceptance and the full application data path.

### Known implementation issues for the next code change

- `cmd/ktest/tls_shape.go`: the automatic MASQUE/F&F calibration is bounded to 15 seconds but the guard does not exclude an explicitly selected `wireguard` method; an uncached network can therefore pay for irrelevant MASQUE measurements.
- `internal/tlsshape/apply.go` and `cmd/ktest/warp_manager.go`: `fragment=off` removes the core's `--fragment` option, but later `aether.WithExitNodes(...)` can add `tlshello-0-len` masked variants. The current setting does not mean “disable every fragmentation mechanism.”
- The calibration probes use uTLS and treat a gateway TLS response as evidence that the ClientHello passed that gateway. Aether uses its own native TLS stack; a calibration pass is only a ranking hint, not a byte-identical fingerprint match or a working-tunnel result.
- Android Balanced/Fast start nine ByeDPI strategy processes plus an optional Xray local core. This is an observed implementation choice; resource cost has not been benchmarked and should not be described as optimal yet.
- Android `tun_running_unverified` and a listening proxy indicate local readiness, not end-to-end Internet access. The UI/diagnostics must preserve that distinction.

See [CURRENT_AUDIT_2026-10-21.md](CURRENT_AUDIT_2026-10-21.md) for the current acceptance matrix.

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

The documentation-only address above is from RFC 5737; replace it with your own test endpoint. Results are one JSON object per line. Exit status 0 means HTTP status 2xx (and matching proof when enabled), status 1 means the response or connection did not satisfy the criterion, status 2 means invalid arguments.

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


## Stage P3: independent transport-layer path diagnosis

Cross-platform binaries are attached to the GitHub Actions `verify` workflow run as short-lived artifacts after a successful build. Each includes SHA-256 checksums. No installation or permanent machine configuration is required.

```sh
ktest path -url https://YOUR-AUTHORIZED-DOMAIN/__ktest/proof -network tcp4
ktest path -url https://YOUR-AUTHORIZED-DOMAIN/__ktest/proof -network tcp6
```

To distinguish failure of normal DNS from failure to reach one **authorized pinned route**:

```sh
ktest path -url https://YOUR-AUTHORIZED-DOMAIN/__ktest/proof -connect YOUR-AUTHORIZED-IP:443
```

The JSON separates `dns_status`, `tcp_status`, `tls_status` and respective error/timing fields. Certificate validation is required; **path** sends no HTTP request or challenge, so `tls_verified_no_http_test` is not evidence that a web application is accessible. Use `ktest probe -proof` for that separate test.

| Date (UTC) | ID | Environment | Experiment | Result |
| --- | --- | --- | --- | --- |
| 2026-10-13 | LOCAL-007 | Go loopback HTTP/TLS servers | Independent DNS, TCP and verified TLS; no HTTP request | Passed locally |
| 2026-10-13 | LOCAL-008 | Go loopback TLS | DNS fails but pinned TCP/TLS still succeeds | Passed locally |
| 2026-10-13 | LOCAL-009 | Go loopback TLS | Self-signed certificate is rejected; TCP success is preserved separately | Passed locally |
| 2026-10-13 | IRAN-005 | Iranian mobile/fixed ISP | IPv4/IPv6 path comparison on controlled targets | Not conducted |
