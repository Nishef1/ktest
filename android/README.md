# KTest Android — Go core with a native UI

Android is a **thin client of the existing KTest Go core**. Network protocols, route policy, foreign-exit checks, ECH/CDN diagnostics and SOCKS5 proxy logic must not be duplicated in Kotlin.

## Single-source architecture

- `cmd/ktest`: original CLI and its platform-dependent orchestrators.
- `internal/smartproxy`: shared Go adaptive TCP/SOCKS engine.
- `internal/connectionpolicy`: shared CLI and Android routing policy and mode catalog.
- `internal/egresscheck`: **shared foreign egress verification**. CLI `probeForeignExit` and Android `verifyLocalUpstream` now call the same Go HTTPS trace policy.
- `mobilebridge`: narrow Go API consumed by `gomobile bind` (status, start/stop, diagnostics, route verification and VPN capability).
- `android/app`: English-only Compose UI, foreground service and Android OS adapter. No duplicated Tor/HEV/Psiphon transport implementations.

## Current mode parity

The Go policy catalog has all seven desktop modes, but **not every launcher is available** on Android.

| Original CLI mode | Android status |
| --- | --- |
| Balanced | Go in-process plain and ClientHello-splitting proxy subset |
| Fast | Same Go subset with shared Fast policy |
| Aether | Optional existing CLI-style external loopback SOCKS5 exit only |
| Aether to Tor | Disabled until the managed CLI transport can run on Android |
| Windscribe | Disabled pending portable original WStunnel / Xray / ByeDPI orchestration |
| Aether to Psiphon | Disabled; the CLI requires managed Aether Psiphon profiles |
| Windscribe through Aether | Disabled until the original two-core carrier is portable |

This is *not yet feature parity* with `connectSession` because the original CLI starts external binaries, profiles and helpers and performs platform-specific network changes. Do not report desktop-dependent routes as Android connections without porting that code.

## Android VpnService adapter

`KTestVpnService.kt` is an **OS adapter**, not an independently implemented VPN protocol.

The Android service:
1. Checks `Mobilebridge.vpnCapability()` from the Go core. **If unavailable, it does not establish a TUN or reroute traffic.**
2. When the Go core can truly forward TCP/UDP, DNS and IPv6 through a verified dataplane, requests permission via `VpnService.prepare` from a real UI interaction.
3. Maps `Mobilebridge.vpnTunPlan()` (Go-owned MTU, addresses, routes and DNS) to `VpnService.Builder`.
4. Calls `Mobilebridge.attachVpnTun(fd)` and only reports a running *packet adapter* if the Go-controlled backend succeeds.
5. Stops the packet adapter and closes the Android-owned fd on Disconnect, revoke or process destruction.

**Today this adapter is intentionally disabled.** KTest's existing `internal/smartproxy` only supports SOCKS5 TCP CONNECT; it has no UDP ASSOCIATE or DNS packet forwarding for HEV. Go's current `coreSOCKSUDPReady=false` and `coreIPv6VPNReady=false` are hard safety gates. There is **no registered native packet adapter**. Therefore this code is useful platform wiring, but **not a working whole-device VPN**, and neither Android consent nor obtaining a TUN fd is treated as connectivity.

The app UID is excluded from the TUN if a future supported Go packet dataplane is activated, to prevent upstream feedback loops. As Android documents, that app's own networking is then outside its VPN coverage; user's other apps remain in its routing scope. Alternative `protect(fd)` per Go socket may be evaluated when the Go core's Dialer can support it.

## Retained functionality

- Shared Go proxy mode routing, bounded foreign-exit checking and app-facing SOCKS5/HTTP proxy.
- Network DNS/TCP/TLS diagnostics, CDN fronting and ECH tests provided by existing Go packages.
- MITM/CA source remains intact in Go; it is not installed on Android.
- English UI with animated Connect/Disconnect, Tools, Settings and manual update checks.

## Release gate

**Do not run the APK/AAR workflow without approval.** `.github/workflows/android-build.yml` remains **manual-only**. Go CI runs formatting, vet, Linux/Windows tests and race tests without creating Android APKs or feature-branch distributable artifacts.

Before calling this an Android port complete: extract portable components of `cmd/ktest/connectSession` into reusable Go packages, port the actual managed Aether/Tor/Psiphon/Windscribe launcher contracts, provide an audited packet dataplane supporting DNS/UDP/IPv6 if whole-device VPN is needed, and validate Android native Gradle + physical phones and real networks. The new Android code is **not yet compiled or device-tested** under the no-build request.
