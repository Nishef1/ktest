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
