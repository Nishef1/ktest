# KTest Android — Go core with a native UI

Android is a **thin client of the existing KTest Go core**. Network protocols, route policy, foreign-exit checks, ECH/CDN diagnostics and SOCKS5 proxy logic must not be duplicated in Kotlin.

## Single-source architecture

- `cmd/ktest`: original CLI and its platform-dependent orchestrators.
- `internal/smartproxy`: shared Go adaptive TCP/SOCKS engine and RFC 1928 UDP ASSOCIATE. Non-DNS datagrams require a verified foreign loopback transport with a working UDP relay, and never fall back to a direct UDP socket.
- `internal/connectionpolicy`: shared CLI and Android routing policy and mode catalog.
- `internal/connectionsession`: shared SOCKS/HTTP/probe listener lifetime, failure propagation and stream cancellation. Both `connectSession` and Android use this package; desktop native-core discovery/launch is still outside it.
- `internal/aether`: the original CLI method/profile catalog, mode filters, identity requirements, private identity validation, staged enrollment transaction, command construction and native process launcher. CLI now uses this shared implementation. Android can inspect the same catalog and checksum-pinned native package through `mobilebridge`.
- `internal/coreprocess`: shared scoped native process execution, cancellation and descendant cleanup on Windows/Unix/Android. The terminal adapters retain no independent process registry.
- `internal/connectiondns`: shared trusted hostname resolution and Android packet DNS. Complete UDP/TCP DNS messages use certificate-verified wire DoH, preserving record types and negative answers.
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

**Today this adapter is intentionally disabled.** Go now implements UDP ASSOCIATE, encrypted wire DNS for UDP and TCP, and IPv6 SOCKS destination encoding. Loopback integration tests cover these paths, TCP control-socket shutdown and removal of a verified exit. Those tests do **not** validate a public dual-stack UDP exit or an Android HEV/TUN dataplane. `coreSOCKSUDPReady=false` and `coreIPv6VPNReady=false` remain end-to-end readiness gates. `VpnCapability` distinguishes implemented protocols from VPN readiness. The service registers HEV when created, but a library existing or starting is insufficient to pass these gates.

The app UID is excluded from the TUN if a future supported Go packet dataplane is activated, to prevent upstream feedback loops. As Android documents, that app's own networking is then outside its VPN coverage; user's other apps remain in its routing scope. Alternative `protect(fd)` per Go socket may be evaluated when the Go core's Dialer can support it.

## Retained functionality

- Shared Go proxy mode routing, bounded foreign-exit checking and app-facing SOCKS5/HTTP proxy.
- Network DNS/TCP/TLS diagnostics, CDN fronting and ECH tests provided by existing Go packages.
- MITM/CA source remains intact in Go; it is not installed on Android.
- English UI with animated Connect/Disconnect, Tools, Settings and manual update checks.
- Diagnose can select automatic TCP, IPv4 or IPv6; connection startup exposes its verification phase and supports cancellation/reconnect.
- CDN scan uses the CLI's Cloudflare/Akamai/Fastly/Google candidate policy and HTTPS scanner, with a 1..300 budget, 90-second ceiling, progress and cancellation. Some providers have a small seed inventory or depend on DNS bootstrap; this is not an unrestricted scan or proof of arbitrary fronting.
- Windscribe carrier testing uses the shared Go WStunnel/Stealth probe for one explicit entry and certificate-valid hostname. This does not implement the desktop node catalog/SNI comparison, OpenVPN authentication, official app integration or an operational Windscribe VPN.
- `TestFronts` exposes the original bounded multi-edge comparison and controlled-origin proof API; the existing GUI retains its one-edge form.

## DNS is an observed path, not an availability guarantee

DoH, DoT, ECH, resolver IPs, TLS names and carrier protocols can be filtered independently. This app does not assume that encrypted DNS works in Iran, and does not implement a DoT fallback. Wire DoH tries bounded independent endpoints with hedging; a silent first endpoint does not consume the whole budget before alternatives begin. Strict modes send these requests through their verified SOCKS exit and never enable direct ECH/system DNS as an escape from that policy. Balanced/Fast's existing hostname resolver can use the system-first trusted-resolver policy; **packet DNS** has no plaintext fallback.

Packet DNS failures appear separately in proxy status and the connection screen. They are transport observations, not proof that the Internet, destination, or all DNS methods are unavailable. In-country availability and censorship causes still need measurements. See [network diagnosis](../docs/NETWORK_DIAGNOSIS.md).

## Source verification without APK/AAR output

`bash android/scripts/check-sources.sh` generates the actual gomobile Java API and compiles it with the pinned HEV 2.19.0 Java declarations, then runs `:app:compileDebugKotlin` in a temporary copy. It requires Linux, Go, JDK 17+, Android platform 36 and Gradle 9.5.0. It leaves `go.mod`/`go.sum` unchanged and builds **no native libraries, AARs or APKs**. Go CI includes this source check and formatting of `mobilebridge`.

Passing it establishes Java/Kotlin source compatibility, including callback signatures. It does not establish native linkage, JNI loading, rendered UI, device traffic, leaks, battery use or reconnect on a phone. The native-release workflow remains manual and separate.

## Native Aether packaging

The official v2.3.0 release includes dedicated Android arm64, ARMv7 and x86_64
archives. `internal/aether/android-cores.json` pins each archive and every
unmodified Aether, Psiphon and Lyrebird executable. It is shared by the Python
packager and the Go runtime verifier; a missing, modified or wrong-ABI bundle
cannot be accepted as a native core installation.

```sh
# Download/verify official artifacts and ELF architecture/linker/page alignment.
# This produces no APK/AAR and does not start a tunnel.
python3 android/scripts/prepare-native-cores.py --verify-only

# Explicit native preparation for the manually gated packaging workflow.
python3 android/scripts/prepare-native-cores.py
```

The native directory contains `libaether.so`, `libpsiphon-tunnel-core.so` and
`liblyrebird.so`. These are separate executables, not additional in-process VPN
implementations. Gradle preserves their exact bytes and extracts them to the
read-only `ApplicationInfo.nativeLibraryDir`; the app must never copy them into
writable app storage to execute them. The manual workflow verifies their hashes
again inside the final APK. It has **not** been dispatched as part of this work.

The shipped ABI set remains ARMv7 and arm64; x86_64 is an optional native-check
target. The pinned arm64 executables meet at least 16 KiB ELF load alignment.
The x86_64 helper executables have 4 KiB alignment and are not a claim of 16 KiB
emulator/device support.

Observed native evidence: the pinned x86_64 Aether and Psiphon executables ran
their help/version commands on `emulator-5554`, outside the app sandbox, without
starting a tunnel or registering credentials. This proves base executable
compatibility on that emulator, **not** execution under the app UID, managed
network connectivity, a Tor circuit, whole-device routing or leak protection.

The source API now exposes `AetherProfileCatalog` and `InspectAndroidBundle`.
Connecting the shared supervisor/enrollment flow to Android's connection service
is still required; profile definitions or packaged files alone are not an active
Aether/Psiphon/Tor connection.

## Release gate

**Do not run the APK/AAR workflow without approval.** `.github/workflows/android-build.yml` remains **manual-only**. Go CI runs formatting, vet, Linux/Windows tests and race tests without creating Android APKs or feature-branch distributable artifacts.

Before calling this an Android port complete: finish extracting native-core orchestration from `cmd/ktest/connectSession`, package the actual managed Aether/Tor/Psiphon/Xray/ByeDPI/Windscribe contracts for Android, and validate the complete native HEV/JNI packet path on physical phones and real networks. An Aether release supporting Termux is not automatically an app integration: Android 10+ restricts executing downloaded files from a writable app home. Native packaging must meet [Android's executable-code rules](https://developer.android.com/about/versions/10/behavior-changes-10#execute-permission), rather than adding a download-and-exec workaround.

### Implementation status, 2026-10-17

| Area | Implemented in source | Still required |
| --- | --- | --- |
| Shared Go connection | SOCKS/HTTP/probe lifetime; Aether profiles, identity/enrollment contracts and scoped native process execution | Complete shared supervisor and Android connection integration |
| Balanced / Fast | Existing Go TCP routes, packet DNS and verified-exit UDP | Xray/ByeDPI/native strategy bundle and device evidence |
| Aether | External SOCKS path; shared native profile/enrollment implementation; pinned Android packaging and runtime verification | Wire managed supervisor/enrollment to Android and validate actual native sessions |
| Tor / Psiphon | Existing desktop implementations preserved | Managed Android transport integration |
| Windscribe / through Aether | Shared carrier probe exposed to Android | Operational native bridge, catalog/profile integration and authenticated data |
| UDP / DNS | Real SOCKS UDP, wire DoH, DNS over UDP/TCP, no direct UDP fallback | Public-exit data-plane tests and HEV/TUN validation |
| IPv6 / whole-device VPN | IPv6 packet encoding and platform wiring | Dual-stack public egress, leak tests and device approval gates |
| CDN / ECH tools | Shared four-provider scanner, one-route front/ECH UI, multi-edge Go API | Full CLI tool parity and rendered/device verification |
| MITM / CA | Go implementation preserved, no automatic trust changes | Explicit Android consent/trust flow and optional activation |
| Verification / release | Go checks, ARM bridge package compilation, source checks, official native payload verification and limited x86_64 executable checks | App-UID native execution, JNI/TUN/device/network/battery/reconnect/signing validation; APK/AAR release remains gated |
