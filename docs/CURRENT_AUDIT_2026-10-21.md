# Current source, CI and performance audit — 2026-10-21

**Reviewed source:** [`978e0ab`](https://github.com/Nishef1/ktest/commit/978e0ab487e086ed5da61478f313db60bf272365) on `main`.
**Scope:** source/documentation review, CI status inspection and the 2026-10-21 ECH DNS follow-up. The reviewed baseline predates the Android connection-lifecycle patch now recorded in the repository. The ECH follow-up adds two pinned-IP AliDNS RFC 8484 candidates to packet DNS; the Android lifecycle patch adds immediate UI state, bounded recovery and idempotent TUN teardown. CI and physical-device acceptance for these follow-ups remain pending.

## Verified CI at the reviewed source snapshot

| Workflow | Result | What it establishes |
| --- | --- | --- |
| [Verify](https://github.com/Nishef1/ktest/actions/runs/39603654030) | Passed | Ubuntu/Windows Go tests, formatting, race tests and Android source checks |
| [Android APK build](https://github.com/Nishef1/ktest/actions/runs/39603653990) | Passed | The workflow produced the configured APK build |
| [Windows portable build](https://github.com/Nishef1/ktest/actions/runs/39603653941) | Passed | The workflow packaged the Windows portable artifact |

These results do **not** prove end-to-end Android TUN traffic, current reachability on a particular Iranian ISP, authenticated application access, feeds/media playback, zero leaks, or good CPU/RAM/battery efficiency. The current source snapshot still needs the physical-device and live-network acceptance tests below.

## Current mode contract

| Mode | Current routing contract | Important limit |
| --- | --- | --- |
| Balanced | Local-first adaptive routing; managed exit discovery after local failure/stall | No AI/TikTok-specific routing exception; local/direct routes can win. No universal access guarantee. |
| Fast | Local-first adaptive routing with a shorter 125 ms head start; native Aether exits on demand | Excludes Psiphon, Tor and unidentified external SOCKS; no AI/TikTok-specific exception. |
| Aether | A working WARP carrier is required for all managed traffic | The WARP public IP may geolocate to Iran; this mode is not a foreign-IP guarantee. |
| Aether to Psiphon | Managed traffic uses the Psiphon backend only | Requires verified non-Iran/non-Russia egress; fail closed when unavailable. |
| Aether to Tor | Managed traffic uses Tor only | Requires a verified Tor circuit and non-Iran/non-Russia exit; exit IP can rotate. |
| Windscribe | Desktop local-only anti-DPI/bootstrap bridge | Does not itself provide a foreign exit; Android does not expose this mode. |
| Windscribe through Aether | Explicit WARP carrier for Windscribe OpenVPN TCP; Windscribe owns final VPN IP | Carrier may be Iran-geolocated; a ready carrier or HTTP CONNECT 200 is not authenticated VPN success. Android mode unavailable. |

## ECH DNS follow-up (2026-10-21)

A report described filtering UDP DNS queries for HTTPS records (type 65) used to obtain ECH configurations, while AliDNS DoH worked on that reporter's network. This is not evidence of a nationwide block and is not the same as blocking ECH handshakes. KTest's direct ECH bootstrap already uses Cloudflare IP literals over TCP/443 with a dummy ECHConfig and accepts the current retry configuration returned by the edge; it does not require DNS and does not hardcode a permanent ECH key.

The packet-DNS endpoint list now includes RFC 8484 DoH at `https://dns.alidns.com/dns-query`, pinned to `223.5.5.5:443` and `223.6.6.6:443`, with TLS certificate validation for `dns.alidns.com`. This can carry HTTPS/SVCB queries through HTTPS if the endpoint is reachable. A unit test verifies endpoint configuration, but real network acceptance and TLS/record-type compatibility on target ISPs remain open.

## Android connection lifecycle follow-up (2026-10-21)

The Android connect/disconnect report exposed two likely contributors: the UI's single 900 ms polling loop mixed connection state with slower VPN/route/CDN diagnostics, and a canceled startup could remove the foreground notification while the serialized reconnect worker was still shutting down the previous session. The follow-up separates fast connection-state polling from slower diagnostics, gives the button immediate local Connecting/Disconnecting states, and keeps the foreground service alive while STOP/RECONNECT owns teardown. The UI no longer calls Go status APIs synchronously during Compose initialization; button color and spinner transitions are shorter.

Unexpected loss of an already-active Go proxy or Android packet adapter now uses the existing serialized reconnect path, bounded to two automatic recovery attempts per user-started session. Explicit user disconnect clears the active request and cancels pending recovery, so it must not reconnect itself. Go's `StopVpnTun` is now idempotent after its fd/adapter state is cleared, avoiding duplicate native process teardown when both proxy and Android service teardown call it. `ProxyService` also avoids enqueuing a second VPN-stop action while the VPN service is already stopping.

These changes are code-level corrections, not a claim that the original field failure has been reproduced or fully diagnosed. The Android APK/Go CI must pass, then a physical phone should be tested for rapid taps, connect/cancel during startup, 20 connect-disconnect cycles, Wi-Fi↔cellular handover, background/resume, VPN permission revocation and sustained traffic. Record the device, Android version, mode, network and logs for any remaining drops.

## Android DNS resolver testing and adaptive fallback (2026-10-21)

The Android Tools screen now has a DNS resolver test that accepts up to 12 IP-literal DNS servers (optional port), queries A records over UDP and TCP without using system DNS for the probe, and tests TLS against the returned public addresses. A resolver is recommended only if it returns a usable public DNS answer and at least one verified HTTPS/TLS handshake succeeds. A DNS reply alone is not reported as Internet access.

A selected IP resolver is stored in app preferences and applied on the next connection for Balanced/Fast and the optional local anti-DPI carrier. Custom DNS is an explicit plaintext opt-in; if it fails, the existing encrypted DoH endpoint set remains available. Aether/Psiphon/Tor protected packet DNS continues to require the verified exit and ignores the plaintext override, preventing a user preference from bypassing strict DNS isolation. Automatic DNS restores the built-in adaptive encrypted resolver policy.

Aether Auto with the local anti-DPI carrier now retains direct H3/WireGuard attempts while adding separate H2 carrier variants. Only compatible TCP/H2 profiles are carried; UDP/H3 profiles are not silently forced through TCP SOCKS. The dedicated Aether mode remains WARP-only. When no external SOCKS upstream is configured, Balanced is the recommended first-run policy: it warms independent WARP, Psiphon and Tor discovery in parallel, so Psiphon/Tor bootstrap does not wait for a WARP identity/key. Fast intentionally remains the lower-latency WARP/local-route policy and does not warm Psiphon/Tor on startup.

The Go/Android CI build and physical-device acceptance for these changes remain pending. Device checks should cover resolver scans with blocked/working UDP and TCP, automatic resolver reset, selected DNS on the next Balanced/Fast connection, strict-mode DNS isolation, first-run with missing WARP identity, and Auto with H2 blocked but H3/WireGuard available.

## Performance architecture observed in source

- Balanced/Fast Go SmartProxy uses a maximum of six simultaneous route attempts. The initial preferred-path head start is 200 ms for Balanced and 125 ms for Fast; these are policy constants, not measured end-to-end latency.
- Android Balanced/Fast launch nine ByeDPI strategy processes and can launch one additional official Xray local core. ByeDPI listeners are checked concurrently with a bounded readiness wait. The design increases available candidates but may increase idle resource use; **RAM, CPU, thermal and battery costs have not been measured**.
- Aether MASQUE TLS-shape/F&F calibration has a 15-second caller budget when its per-network/options cache is missing or stale. It is independent of the website-target diagnostic sweep. The current guard skips Psiphon/Tor but does not skip an explicitly selected WireGuard method, so a WireGuard-only selection can pay for irrelevant MASQUE calibration.
- The calibration uses uTLS to compare TLS handshakes against candidate WARP HTTP/2 gateways. A gateway response means the ClientHello reached that gateway; it does not prove the Aether tunnel, CONNECT-IP, foreign egress or application HTTPS works. Aether uses its own native TLS implementation, so the measured fingerprint is a ranking proxy, not a byte-identical native ClientHello.
- `fragment=off` removes Aether's built-in `--fragment` option in `internal/tlsshape/apply.go`, but `aether.WithExitNodes(...)` can subsequently add `tlshello-0-len` variants. The current setting does not guarantee that every fragmentation mechanism is disabled.
- The Android UI/service can report local proxy/TUN readiness (`tun_running_unverified`). That is not an end-to-end Internet check. Keep listener, packet-adapter, verified-exit and destination HTTPS states separate.
- ECH bootstrap is shared across callers and caches a successful configuration for ten minutes or a definite failure for five minutes; automatic native startup waits only a short caller budget for it and can continue with non-ECH profiles. A failed ECH lookup is not proof that all ECH or all Internet paths are blocked.

## Known issues and next engineering steps

| Priority | Issue | Required follow-up |
| --- | --- | --- |
| P1 | MASQUE calibration can run for a forced WireGuard method | Fixed in the Android/terminal parity candidate: explicit non-MASQUE methods skip calibration; regression tests cover WireGuard, wiw and helper backends. CI pending. |
| P1 | `fragment=off` did not suppress TCP TLS-hello exit-node masks | Semantics are now explicit in the parity candidate: `off` disables Aether's native TLS fragmentation and excludes TCP TLS-hello exit-node variants in both CLI and Android automatic-exit profiles; independent UDP-noise and local-carrier strategies remain. Regression tests added; CI pending. |
| P1 | Android native Aether profiles did not consume saved MASQUE calibration | Fixed in the parity candidate: pass the private directory into explicit/Auto profile selection, use the cached result for shaping and ordering, and set the network cache key before native startup and manual measurement. Regression test added; CI pending. |
| P2 | No quantitative performance evidence | Benchmark cold/warm startup P50/P95, first HTTPS, verified exit, CPU/RAM, thermal behavior and 30–60 minute battery drain on representative physical Android devices; compare with previous release on the same device/network. |
| P2 | Readiness can be mistaken for Internet availability | Add/retain distinct states for proxy listener, TUN adapter, verified carrier/foreign exit and destination HTTPS. Do not label a listener or `tun_running_unverified` as Internet verified. |
| P2 | Current-commit live network acceptance incomplete | Test 20 disconnect/reconnect cycles, Wi-Fi↔cellular handover, DNS including HTTPS RR/ECHConfig over AliDNS DoH, UDP/IPv6, ECH, TUN failover, DNS/IPv6 leaks, and authenticated page/API/media flows on a physical phone. Record commit, network, method and exact result. |
| P3 | Historical docs can look like current guarantees | Keep dated observations explicitly historical; update the living contract in `USAGE.md`, `CONNECTION_MODES.md`, `NETWORK_DIAGNOSIS.md` and `android/README.md`. |

## Acceptance checklist

- [ ] Current `main` CI passes after documentation updates.
- [ ] Physical Android test on at least one ARM64 device and Android 10+; include Android 16 KiB page-size device if available.
- [ ] Confirm local readiness and end-to-end HTTPS are reported separately.
- [ ] Run the same benchmark on the previous release and current candidate with the same network and device.
- [ ] Validate DNS including HTTPS RR/ECHConfig retrieval over each AliDNS pinned DoH endpoint, UDP/443, IPv6, TUN fallback, app-UID exclusion, leaks and network handover.
- [ ] Validate Aether Auto, explicit WireGuard, MASQUE H2/H3, Psiphon and Tor separately; distinguish carrier ready from authenticated/verified exit.
- [ ] Validate Windscribe only through its own authenticated VPN data plane; never infer success from a bootstrap response.

## Source locations reviewed

- [`cmd/ktest/tls_shape.go`](../cmd/ktest/tls_shape.go)
- [`internal/tlsshape/apply.go`](../internal/tlsshape/apply.go)
- [`internal/tlsshape/calibrate.go`](../internal/tlsshape/calibrate.go)
- [`cmd/ktest/warp_manager.go`](../cmd/ktest/warp_manager.go)
- [`mobilebridge/local_cores.go`](../mobilebridge/local_cores.go)
- [`mobilebridge/local_xray.go`](../mobilebridge/local_xray.go)
- [`android/app/src/main/java/com/nishef/ktest/ProxyService.kt`](../android/app/src/main/java/com/nishef/ktest/ProxyService.kt)
- [`internal/connectionpolicy/policy.go`](../internal/connectionpolicy/policy.go)
- [`internal/smartproxy/udp.go`](../internal/smartproxy/udp.go)

No runtime code is changed by this audit document.