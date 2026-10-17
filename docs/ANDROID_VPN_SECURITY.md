# Android VPN integration: safety gates and architecture

Status: design and test harness only; not yet an end-user VPN feature. **Do not enable, distribute or market as a complete VPN until the gates below are met.**

## Source-based findings (checked 2026-10-17)

1. Android `VpnService` creates the TUN interface; it is not a built-in tun2socks engine: https://developer.android.com/develop/connectivity/vpn
2. Android requires protecting upstream sockets before connecting them, or preventing them from being routed back into the VPN: https://developer.android.com/reference/android/net/VpnService#protect(int)
3. **Simpler candidate** for this app: `Builder.addDisallowedApplication(packageName)` excludes our entire Go/HEV app UID from the VPN routes, avoiding JNI per-socket protect hooks for our own Go sockets. This means KTest's *own* diagnostic and other network traffic bypass the VPN, not that those packets gain privacy protection. It must be tested against lockdown/always-on policies and OEMs. https://developer.android.com/reference/android/net/VpnService.Builder#addDisallowedApplication(java.lang.String)
4. HEV's upstream has an Android AAR exposing `hev.htproxy.TProxyService` with native `TProxyStartService(configPath, fd)`, `TProxyStopService()`, `TProxyIsRunning()`, `TProxyGetStats()`. Android-specific assets must be pinned and integrity-checked; do not ship downloaded executables at runtime: https://github.com/heiher/hev-socks5-tunnel
5. HEV supports UDP **only if the selected SOCKS path supports the negotiated UDP mode**. Our local Go SOCKS5 listener currently supports **CONNECT/TCP only**. Wiring HEV directly to it would break DNS/QUIC/UDP; do not do that. HEV config specification: https://github.com/heiher/hev-socks5-tunnel/blob/main/conf/main.yml
6. Tor can be packaged using Guardian Project's native Tor Android library (Maven Central `info.guardianproject:tor-android`), but needs an authenticated Tor bootstrap/circuit state, not merely an open local port: https://github.com/guardianproject/tor-android
7. Psiphon has an Android AAR; working integration requires a valid, permitted client configuration including its sponsor/channel keys and transport/server-list settings. Review GPL licensing before integrating: https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/MobileLibrary/Android/README.md
8. Aether/Zeptun integration depends on a buildable **Android** library/entrypoint. Existing Windows external-process launchers cannot be copied unchanged.

## Design target

```text
Android Compose (English)
  -> explicit user VPN permission
  -> foreground VpnService + lifecycle/revoke handler
  -> HEV TUN-to-SOCKS (single pinned AAR; stop on failure)
  -> UDP-capable, locally authenticated SOCKS transport
  -> Aether / Psiphon / Tor / other verified foreign exit
  -> real HTTPS and UDP test endpoints
```

The Go core remains primary for Balanced/Fast, diagnostics, ECH, fronting and route policy; no Rust rewrite. Only one transport engine should own the TUN at a time.

## Preconditions to enabling the VPN toggle

- [ ] Confirm the selected upstream is live, with verified TLS and foreign egress according to the user's chosen privacy policy. No direct ISP fallback for external-only modes.
- [ ] Confirm **actual UDP relay DNS response** using `CheckUDPRelay` (not just the SOCKS5 UDP ASSOCIATE reply). Do not assume an IPv4 result proves IPv6 transport.
- [ ] Pin, audit and bundle HEV's upstream Android AAR/JNI artifact for each supported ABI with a recorded SHA-256 and license notice. No unpinned `latest` dependency at release.
- [ ] Confirm the HEV UDP mode matches the negotiated SOCKS provider and reject unsupported modes; avoid UDP blackholes or direct leaks.
- [ ] Obtain `VpnService.prepare()` consent on foreground user action and check for revocation and permission changes.
- [ ] Create consistent TUN address + route + DNS: do not use the system/default resolver without an explicit trusted path. Route DNS/UDP and IPv6 through verified backend or block those address families explicitly; never make an implicit bypass decision.
- [ ] Prove that all upstream Go/HEV sockets are outside VPN routing, through scoped `protect(fd)` or `addDisallowedApplication(packageName)`. Confirm the exclusion does not leak user-app traffic. Never invoke global `allowBypass()` silently.
- [ ] Keep a foreground notification and stop immediately if the VPN interface or native tunnel dies. Android's `onRevoke()` must stop the native component and close TUN FD.
- [ ] Implement shutdown + fast reconnect, process kill/restore, airplane mode, dual-SIM, Wi-Fi-to-LTE, foreground/background, captive portal, and Android always-on/lockdown tests.
- [ ] Be explicit that the Android system may permit non-VPN traffic between unexpected tunnel teardown and recovery unless the user enables Android's block-without-VPN setting. Never promise an app-level kill switch that isn't implemented.
- [ ] Run DNS/IPv6/WebRTC leak checks on physical ARM32/ARM64 devices, with separate IPv4-only and dual-stack networks.
- [ ] Benchmark energy usage on real phones before saying HEV is better than sing-box.

## HEV configuration shape (not yet activated)

```yaml
tunnel:
  name: tun0
  mtu: 1500
  ipv4: 198.18.0.1
  icmp: 'off'

socks5:
  address: 127.0.0.1
  port: 1080 # replace with a validated local, UDP-capable SOCKS server
  udp: 'udp'
misc:
  log-level: warn
```

Note: these illustrative addresses are **not** user VPN credentials, are not a working deployment config and must not be hardcoded as an available connection. A UDP-capable backend must be in place and tested before establishing routes.

## Native core roadmap, in order

1. Finish device-independent DNS/TCP/TLS + SOCKS UDP preflight with bounded, deterministic tests. Preserve direct vs verified exits and real state reporting.
2. Prepare a native HEV runtime adapter, pin its AAR and validate each ABI on physical Android devices; do not yet enable all-app routing.
3. Wire `VpnService` with explicit permission, FD lifecycle, Android app UID exclusion or protected sockets and verified DNS/IPv6 behavior.
4. Integrate one embedded *real* foreign-exit core at a time: Tor Android first because a maintained Android-specific AAR exists; Psiphon after configuration/license review; Aether after Zeptun Android dataplane review. Preserve existing CA-based fronting as an explicit opt-in research capability.
5. Bring in real connectivity verification, network reconnection, UI state machine, accessibility/power tests and stable signed production releases.

## Known constraint

The experimental local Go SOCKS5 server (Balanced/Fast) currently **rejects UDP ASSOCIATE**, so it is intentionally **ineligible** for a full HEV VPN unless its UDP implementation is completed or HEV targets a different UDP-capable verified SOCKS backend. A false VPN-success indicator here would be worse than keeping proxy-only mode enabled.
