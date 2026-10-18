# Zapret2 Windows integration decision (reviewed 2026-10-18)

Status: **Windows A/B pilot and explicitly selected experimental Windscribe bridge implemented (2026-10-18); no real ISP/device packet-capture result has been measured.** The bridge now detects the app's requested node through its existing HTTP CONNECT path. Packet manipulation stays off in ordinary local-bridge sessions. This document does not establish success on any Iranian ISP; general/default enablement still requires live validation.

Upstream: https://github.com/bol-van/zapret2 (latest release verified 2026-10-18: v1.0.5.2). The original zapret1 is EOL and must not be chosen for new integration. Official docs:
- https://github.com/bol-van/zapret2/blob/master/docs/readme.md
- https://github.com/bol-van/zapret2/blob/master/docs/manual.en.md
- https://github.com/bol-van/zapret2/blob/master/docs/compile/build_howto_windows.txt
- https://www.reqrypt.org/windivert-doc.html

## Architectural decision

**Integrate winws2 as an opt-in Windows packet-layer controller, never as a `smartproxy.Upstream` or as a replacement for `ciadpi`, WStunnel, Xray, Aether or Windscribe.** winws2/WinDivert intercepts OS network packets; it does not provide a SOCKS listener. ktest's `internal/smartproxy` ranks *connection transports*, not system-level packet manipulation.

The manual diagnostic compares the same fixed provider-advertised entry and SNI without/with Zapret2. The separate experimental bridge (`connect -mode windscribe -windscribe-zapret fake|split|combo`, menu Windscribe → 3) uses the existing app-provided OpenVPN TCP target and fresh provider catalog. It serializes direct WStunnel attempts, starts a single exact-IP TCP 443 filter before each outer handshake, and stops it before forwarding OpenVPN bytes. Established VPN streams need no resident filter. No blanket TCP/UDP capture or stacking with Xray/ByeDPI/Stealth is enabled on these carriers. CLI-correlated Connected remains separate from transport readiness and is not cryptographic path attribution.

## Exact repository integration points

1. **New `internal/packetdesync` (Windows-only implementation, other platforms return unsupported):** source-pinned binary/Lua/WinDivert bundle validation, controlled `winws2.exe` argv construction, strict IPv4/port/strategy allowlist, filter preview, owned process start/stop, readiness diagnostics and graceful bounded cleanup. No shell invocation. Never terminate third-party Zapret or other WinDivert users by executable name.
2. **`cmd/ktest/windscribe_probe.go`:** first opt-in test call site, receiving one validated provider entry IP from `selectWSProbeNode`; one fixed SNI and carrier type. Run a bounded **serial** A/B comparison, not simultaneous baseline and packet-shaped trials. Preserve individual TCP/TLS/WebSocket evidence and timings. Display a warning that packet filtering can also affect other local processes connecting to that same IP:port.
3. **`cmd/ktest/connect.go`:** `-windscribe-zapret` is explicit, Windows-only and disabled by default. Validation limits it to local Windscribe without TUN, Aether, CDN or entry overrides. Administrator, pinned bundle and CLI checks precede listener preparation. Existing connected/unknown initial VPN state waits for confirmed disconnection. Failure reports the reason without silently selecting an unshaped transport or broadening the filter.
4. **`cmd/ktest/windscribe_wstunnel.go` / `windscribe_zapret.go`:** discovery still follows the exact app-requested TCP node. Packet mode admits one WStunnel candidate at a time; a controller gate also serializes filters across concurrent CONNECT requests. Each selected entry is checked against the fresh provider mapping before starting the filter. The owned process stops after the outer TLS/WebSocket handshake, including failure/cancellation; startup or unconfirmed cleanup blocks further filters for the session. OpenVPN replay, junk packets, CLI state correlation and existing API routing retain their existing owners. A WinDivert process is not an independent SOCKS route or a separately raced VPN winner.
5. **`internal/coreprocess`:** reuse existing process confinement and job-object cleanup (`Command`, `Run`, owned PID/descendants), with explicit tests for termination, early exit and cancellation. WinDivert driver handles may outlive the worker briefly; verify driver/filter release separately on Windows. Do not delete a shared driver service on cleanup.
6. **`.github/workflows/windows-portable.yml`:** bundles the pinned `winws2.exe`, `cygwin1.dll`, `WinDivert.dll`, signed `WinDivert64.sys` and matching Lua helpers with Git blob/SHA-256 and driver signature checks plus license notices. Runtime never downloads these components. Older local portable folders may need the packaged Zapret2 directory before this mode can start.
7. **`docs/WINDSCRIBE_BOOTSTRAP.md` / `docs/CONNECTION_MODES.md`:** document opt-in, privilege request, how to stop, last known network state, source IP unchanged, carrier authentication boundary and exact test outcomes.

## Critical WinDivert interception boundary

WinDivert's `NETWORK` layer filter cannot directly select by process ID; its process ID exists at the `FLOW`/`SOCKET` layer, not on ordinary modifiable packets. Therefore a target IP:port filter is **not process-private**. The initial opt-in must explicitly disclose this and fail closed when there is no exact, verified target. Do not intercept all HTTPS, DNS, QUIC, UDP or LAN traffic.

For `winws2`, upstream documents that `--wf-raw-part` is **OR-combined** with the generated port filters. It cannot safely be used as a narrowing predicate. Instead generate a dedicated reviewed `--wf-raw` filter or compose `--wf-tcp-out=443` with an **AND-combined** `--wf-raw-filter` including the exact target IP in both outbound-destination and inbound-source directions. Validate the final filter with upstream `--wf-save`, and test positive and negative packet samples. Handle IPv6 separately; IPv4-only for phase 1. Exclude loopback and injected/impostor packets as appropriate to prevent capture loops. Never build a filter by interpolating unchecked CLI text.

TUN (`cmd/ktest/tunnel.go`, Wintun/sing-box), WinDivert packet interception, and a running Windscribe VPN are separate system facilities. Refuse simultaneous KTest TUN and packet-desync mode; never manipulate the outer WARP/Psiphon/Tor traffic of strict modes. Prevent conflict with a separately active Zapret/WinDivert filter rather than killing it.

## Experiment order and attribution

- Stage 0: offline binary provenance, driver signature, license review, filter generator/argv tests, Windows process lifecycle tests, mockable diagnostic tests. No administrator rights required for ordinary unit tests.
- Stage 1: administrator-authorized, single IP:443, **one strategy at a time**, same destination and SNI: untouched TLS/WStunnel baseline -> conservative `winws2` fake strategy -> optional packet-level split/sequence-overlap strategy. Choose actual parameter combinations from pinned Zapret2 Lua scripts and test them against the matching binary; never assume that a zapret1 command works on winws2 unchanged. Use short upper bounds for attempts and full cleanup, and ensure all other traffic remains unmodified by the filter.
- Stage 2: once Stage 1 improves an actual blocked baseline on the *same* network, examine stacking with direct Windscribe WStunnel and only later with local Xray/ByeDPI. An earlier stream/TLS split can prevent winws2 from recognizing a complete ClientHello; stacking is not automatically additive. Do not concurrently race different packet-layer filters over the same destination.
- Stage 3: the user-requested explicit experimental bridge is available for these live checks; it is not a validated default. General/default enablement requires multiple matched trials on the same ISP, unchanged official exit authentication, no DNS/IP leak, zero unowned processes left running, and stable disconnect/reconnect. A TLS handshake, HTTP 101 or an OpenVPN-looking control response alone is not proof.

Record: date, local network fingerprint (privacy-preserving), exact target IP and SNI, selected outer carrier, strategy hash/name, starting/stopping process IDs, baseline and shaped failure phase, TLS verification details, WebSocket upgrade, authenticated Windscribe CLI state when available, and strict exit-IP evidence when legitimately measured. Never claim a general Iran bypass from one operator's run.

## Not in initial scope

- No Android winws2/nfqws2 integration, Linux NFQUEUE, TUN reimplementation, system-wide interception, root CA, new exit/VPN protocol, arbitrary Lua editor, untrusted preset downloads, automatic elevation, or permanent driver/service installation.
- No automatic all-method combination. Avoid treating a favorable SOCKS or TCP connection as proof the VPN works.
- Packet desynchronization cannot bypass IP-layer routing allowlists where the destination IP is unreachable, and cannot create a foreign public exit.

## Source review anchors

Existing KTest code: `cmd/ktest/connect.go` (mode, core launch, SOCKS race, Windscribe bridge), `cmd/ktest/windscribe_wstunnel.go` (provider-node carrier construction and 64-candidate race), `cmd/ktest/windscribe_probe.go` (fixed target probe), `cmd/ktest/windscribe_catalog.go` (provider-advertised addresses), `cmd/ktest/tunnel.go` and `internal/systemtun/tun_windows.go` (TUN and Windows privileges), `internal/coreprocess/` (job-object-scoped cleanup), `internal/byedpi/` (existing independently maintained local SOCKS engine).

Upstream: zapret2 `docs/readme.md` (Lua strategy model and OS packet capture), `docs/manual.en.md` (raw filter AND/OR semantics), `docs/compile/build_howto_windows.txt` (winws2, Cygwin and WinDivert dependencies), release CI `.github/workflows/build.yml` (official Windows build/artifact layout); WinDivert documentation (process PID unavailable in NETWORK layer; packet-filter expressions and signed driver behavior).
