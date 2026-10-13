# Engineering roadmap (2026-10-13)

Scope: diagnostic research into direct access to selected filtered services without changing the public egress IP. This repository is **public**. These notes are project notes, NOT secret documentation; never commit credentials, tunnel endpoints, personal IP logs, cookies, user certificates, or sensitive field measurements.

## Ground rules

- No claims of success without reproducible in-country measurements (ISP, access type, timestamp, version, target, baseline and treatment), preferably from multiple networks.
- Preserve TLS certificate verification and explicitly report HTTP 403/421 rather than treating every established connection as a successful bypass.
- Never silently install a trusted root CA, change global routes/DNS, inject firewall rules, or capture other programs' traffic.
- By default use only test destinations that we control or have permission to test; no high-volume scanning.
- Prefer a focused direct-access tool rather than adding a full VPN/TUN stack prematurely.

## Architecture decisions

- **Language: Go 1.27.2 (2026-10-08 security release).** Single binaries across Windows, Linux and macOS, standard-library HTTP/TLS instrumentation, rapid iteration. Consider Rust/native packet adapter only when a measured requirement justifies packet capture/injection. Do not reinvent Xray or Zapret internals.
- `cmd/ktest`: non-privileged and bounded probe CLI.
- `internal/probe`: direct HTTP(S) trials with explicit TCP family (4/6), optional pinned dial address, TLS ServerName, HTTP Host, connection timing and JSONL results. It does not claim to evade DPI.
- Future `internal/strategy`: isolated driver interface for validated external or local-only methods; no automatic risky network modifications.
- Research is separated from tested capability in `docs/RESEARCH.md` and `docs/EXPERIMENTS.md`.

## Phases and gates

| Phase | Deliverable | Exit gate | Status |
| --- | --- | --- | --- |
| P0 | Reproducible direct-network diagnostic: DNS, TCP, TLS, HTTP, IPv4/IPv6, Host/SNI, optional dial override | Local TLS tests and CI pass | Done; initial GitHub Actions passed |
| P1 | Repeatable A/B variants: baseline, pinned dial, HTTP Host, TLS SNI and combined, with phase and status summaries | Local tests and GitHub CI pass; field evidence is a separate gate | Implemented locally; GitHub CI pending |
| P2 | Research adapters for documented TLS-layer differences and standalone Zapret2/ByeDPI/SNI-Spoofing-Go, only after permission and platform fit | Validate at least one repeatable gain over P1 and no breakage | Research only |
| P3 | Opt-in direct service access for a small supported set of hosts, no system-wide CA | Verified certificate handling and leak tests | Not started |
| P4 | Optional system-wide proxy/TUN integration | Prove data-plane consistency, DNS/IPv6 leak prevention, no silent fallback | Deferred |

## Decision gates / possible failures

1. No TCP connection: TLS/SNI adjustments cannot rescue packets discarded before handshake; diagnose routing/IP policy first.
2. TCP works, TLS fails: examine TLS versions, SNI/certificate verification, reset behavior. This is the relevant precondition for TLS-parser differential research.
3. TLS works but HTTP responds 421: host-routed fronting probably rejected by the service; do not misclassify as bypass. See AWS CloudFront guidance.
4. HTTP responds 403: request arrived, but authorization/access denied; do not call it success.
5. HTTP succeeds but end-to-end application fails: app pinning, separate hostnames, QUIC, cookies, DNS, IP-based restrictions and security model require independent investigation.
6. Regional accessibility claims require real on-ISP evidence and must be explicitly time-bounded.

## Pending field evidence

- Anonymous measurements on selected Iranian mobile + fixed ISPs with **opt-in**. Record only aggregate protocol outcomes and coarse network class; keep raw logs off public GitHub.
- Baseline TCP4 vs TCP6 behavior; SNI/Host differences with controlled test services.
- Determine whether an existing Windscribe-connected route can bootstrap data, rather than claiming that a partial Google connection equals VPN egress.
- Review third-party tool licenses and security posture before vendoring or integration.

## P1 implementation notes

- `ktest compare` produces a single JSON object containing samples and per-variant summaries, using 1–10 rounds with alternating order. Execution requires `-authorized`. Certificate verification stays enabled; no root CA is installed.
- Optional `-connect 127.0.0.1:PORT` lets the comparison connect to a separately running local TCP forwarder. This repository neither downloads nor launches privileged packet-desync programs; comparisons are not themselves injected fake ClientHellos.
- JSON output can contain IP addresses, URLs and network error strings. Keep raw field reports off public GitHub.
- Go and CI dependencies were updated after checking upstream release notes. See `docs/UPSTREAM.md`.

## P2: evidence-first adaptive diagnosis (2026-10-13)

- New opt-in `-proof` mode verifies a fresh, random 128-bit challenge echoed by a controlled HTTPS origin. A success-looking 200 without proof, and every 3xx redirect, is **not** accepted as origin reachability. The nonce is not included in JSON results.
- `ktest echo` binds only to loopback. For remote experiments, put it behind the HTTPS reverse proxy of infrastructure you control; do not expose its raw HTTP port.
- `ktest compare -authorized -proof` produces per-variant proof counts plus one cautious machine-readable assessment: `baseline_available`, `candidate`, `inconclusive`, `path_unreachable`, or `unverified`.
- A `candidate` means an alternate path verified *the controlled origin* in all tested rounds while the baseline did not. It is **not** proof of a generally functioning bypass and is not promoted without multiple networks, time windows, and independent verification.
- Intentionally avoid downloading/executing elevated third-party packet injection tools or altering routes in this phase. A failed trial should update the hypothesis, not cause blind retry storms.

### Hypothesis queue / failure-driven ordering

| Observation | Next experiment | Why |
| --- | --- | --- |
| All variants fail before TCP establishment | IPv4 vs IPv6, alternate permitted access network, direct route checks | TLS/parser changes cannot restore a missing IP path |
| TCP works but TLS fails | Compare valid TLS identities, verified certificate, timing and path on controlled endpoints | TLS/SNI inspection or server policy is plausible, not proven |
| TLS works but HTTP 301/302/403/421 | Analyze redirect/authorization/provider routing separately | Never call these proof of internet access |
| 2xx without matching challenge | Treat as unverified/maybe intercepted or cached response | Avoid success false positives |
| One alternate returns repeated valid nonce | Candidate only, then collect paired negative controls and network diversity | Separate temporal fluctuation from causal mechanism |
| Small bootstrap channel available but direct QUIC path works after setup | *Research* QUICstep connection-migration method, only with compatible sites | Potential to reduce traffic in limited channel; no blanket Iran claim |


## P3: independent DNS / TCP / TLS observations (2026-10-13)

- `ktest path` performs low-volume, independent DNS resolution, TCP connection and certificate-verified TLS handshake checks. It sends **no HTTP request** and makes no claim about a working website, tunnel or censorship bypass.
- Uses `-network tcp4` or `-network tcp6` to isolate IP-family reachability. A pinned `-connect host:port` is measured independently of DNS: DNS may fail while pinned TCP/TLS succeeds. TLS errors remain separate from TCP errors.
- Always verify certificate identity; never set `InsecureSkipVerify`. No packet injection, scanning engine, firewall changes or device-wide proxy installation.
- GitHub Actions now builds user-invoked diagnostic executables for Windows amd64, Linux amd64/arm64 and macOS arm64, with SHA-256 manifests. These are temporary workflow artifacts, not public releases or VPN clients.
- **Decision gate:** only after repeatable findings from opt-in, real-ISP controlled-target trials consider a specialized TCP/TLS strategy. QUIC-specific work requires separate UDP path evidence and a QUIC-migration-compatible origin.


## P4: working-method integration (2026-10-13)

The user requested prioritizing already deployed, user-reported anti-DPI tools over an expanding diagnostic test framework. Implemented \`ktest access\`: an explicit domain-scoped HTTP CONNECT proxy and optional lifecycle management for the official, hash-verified SNI-Spoofing-Go v0.7.2 binary. See \`docs/ACCESS.md\`.

Status: **implemented, local pass only**. The upstream engine must still be assessed on an actual filtered network. The MITM-DomainFronting v23 route is deferred due to unresolved failure reports and CA trust implications. We will not claim universal access, a changed public IP, or full-system VPN support.

Next meaningful improvements require a *specific confirmed-working combination* and one real destination that serves it: save only non-sensitive successful combinations, keep automatic profile switching opt-in, and do not broaden to unrelated DPI experiments without evidence.
