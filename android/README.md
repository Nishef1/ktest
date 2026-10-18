# KTest Android — existing native cores with shared Go integration

Android uses the **existing upstream networking cores**, a narrow shared Go integration layer and a native UI. Aether owns MASQUE/WireGuard, native gateway scans/reconnect and its Tor/Psiphon backends. Xray, ByeDPI and Windscribe retain their respective roles. Do not reimplement these engines in Go or Kotlin, or port the entire CLI supervisor as an Android prerequisite. The [engineering roadmap](../docs/ROADMAP.md) records responsibility boundaries, remaining work and the code reuse audit.

Keep Go for required KTest policy, lifecycle, shared diagnostics and existing mixed-mode routing. Prefer the selected core's native SOCKS/HTTP and packet capabilities where they satisfy the mode contract; an additional Go proxy is not a universal requirement. Any simplified path must preserve verified-exit checks, expiry and fail-closed routing.

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
| Aether | Managed packaged core with native method selection; optional existing loopback SOCKS path |
| Aether to Tor | Managed Aether Tor-only backend; Tor Project and foreign-exit checks required before connection is active |
| Windscribe | Disabled pending portable original WStunnel / Xray / ByeDPI orchestration |
| Aether to Psiphon | Managed Aether Psiphon / CDN profiles; bundled shirokhorshid helper, no external SOCKS substitution |
| Windscribe through Aether | Disabled until the original two-core carrier is portable |

This is *not yet feature parity* with `connectSession`. Android must implement the required lifecycle and OS integration of the existing binaries and helpers; it need not copy all desktop orchestration. Do not report a mode as connected until its selected native backend actually runs and its traffic is verified.

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
- English dark UI: animated power control with phase steps (prepare / start core / verify exit), session uptime, copyable SOCKS5/HTTP endpoints and per-target HTTPS verification; Tools as collapsible cards; Settings with manual update checks, packaged-core hash verification (`InspectAndroidBundle`), privacy notes and open-source notices for the shipped AGPL/GPL/BSD/MIT executables. Adaptive launcher icon, monochrome notification icon with a session chronometer.
- Diagnose can select automatic TCP, IPv4 or IPv6; connection startup exposes its verification phase and supports cancellation/reconnect.
- CDN scan uses the CLI's Cloudflare/Akamai/Fastly/Google candidate policy and HTTPS scanner, with a 1..300 budget, 90-second ceiling, progress and cancellation. Some providers have a small seed inventory or depend on DNS bootstrap; this is not an unrestricted scan or proof of arbitrary fronting.
- Windscribe carrier testing uses the shared Go WStunnel/Stealth probe for one explicit entry and certificate-valid hostname. This does not implement the desktop node catalog/SNI comparison, OpenVPN authentication, official app integration or an operational Windscribe VPN.
- The fronting tool uses `TestFronts`: 1..12 edges, 1..3 rounds and optional controlled-origin proof, with per-edge TCP/TLS/HTTP/origin counts. Verified CDN-scan edges can be handed to it directly.

## DNS is an observed path, not an availability guarantee

DoH, DoT, ECH, resolver IPs, TLS names and carrier protocols can be filtered independently. This app does not assume that encrypted DNS works in Iran, and does not implement a DoT fallback. Wire DoH tries bounded independent endpoints with hedging; a silent first endpoint does not consume the whole budget before alternatives begin. Strict modes send these requests through their verified SOCKS exit and never enable direct ECH/system DNS as an escape from that policy. Balanced/Fast's existing hostname resolver can use the system-first trusted-resolver policy; **packet DNS** has no plaintext fallback.

Packet DNS failures appear separately in proxy status and the connection screen. They are transport observations, not proof that the Internet, destination, or all DNS methods are unavailable. In-country availability and censorship causes still need measurements. See [network diagnosis](../docs/NETWORK_DIAGNOSIS.md).

## Source verification without APK/AAR output

`bash android/scripts/check-sources.sh` generates the actual gomobile Java API, then compiles Kotlin against the unchanged checksum-pinned HEV 2.19.0 AAR and merges its actual manifest in a temporary copy. It requires Linux, Go, JDK 17+, Android platform 36 and Gradle 9.5.0. It leaves `go.mod`/`go.sum` unchanged and builds **no native libraries, AARs or APKs**; the existing HEV AAR is downloaded and verified, not rebuilt. Go CI includes this source check and formatting of `mobilebridge`.

Passing it establishes Java/Kotlin source compatibility, including callback signatures. It does not establish native linkage, JNI loading, rendered UI, device traffic, leaks, battery use or reconnect on a phone. The native-release workflow remains manual and separate.

## Native Aether packaging

The official v2.3.0 release includes dedicated Android arm64, ARMv7 and x86_64
archives. `internal/aether/android-cores.json` pins each archive and every
unmodified Aether, Psiphon and Lyrebird executable. It is shared by the Python
packager and the Go runtime verifier; a missing, modified or wrong-ABI bundle
cannot be accepted as a native core installation.

Aether already includes Tor through Arti and ships the Psiphon helper built
from CluvexStudio's `shirokhorshid` branch, pinned to
`83aa73b9b982e7421e00117f5b0c5aceb5dda452`. Use these backends through Aether;
do not add separate Tor/Psiphon implementations or a second helper acquisition
path for this bundle. See [provenance](../docs/THIRD_PARTY_NOTICES.md).

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

Native help/version commands initially ran in the emulator shell. Later
validation builds launched Aether and its Psiphon helper under the app UID on
`emulator-5554`. UI Cancel removed the native parent and helper in about 0.14s;
a forced parent exit also removed the helper and surfaced an error without
publishing a connection. These are lifecycle observations on one emulator,
not proof of native Internet egress or a full-device VPN.

The service now calls `StartNativeProxy` with `ApplicationInfo.nativeLibraryDir` and app-private state. Aether owns initial enrollment, gateway scans and native reconnect; Android does not invoke a second Go enrollment/scanning supervisor. Startup, cancellation and native exit are tied to the shared process runner. The existing Go policy proxy remains to enforce verified-exit leases and protected routing. Aether/Psiphon native execution under the app UID has been observed on emulator-5554; verified foreign egress and sustained native traffic remain separate acceptance requirements.

## Release gate

**Final release remains gated.** The user has now requested the final app after audit/debugging, including UI/UX and documentation; local validation builds are authorized for that work. A validation APK is not a release-ready app. `.github/workflows/android-build.yml` remains **manual-only**. Go CI runs formatting, vet, Linux/Windows tests and race tests without creating Android APKs or feature-branch distributable artifacts.

Before calling this an Android port complete: wire the smallest required native-core lifecycle and mode adapters, use Aether's existing Tor/Psiphon support, complete the remaining Xray/ByeDPI/Windscribe integration, and validate the complete native HEV/JNI packet path on physical phones and real networks. Evaluate HEV directly against a compatible selected core before expanding the Go packet relay; preserve all mode/egress policy and validate each backend's actual UDP/DNS/IPv6 support. An Aether release supporting Termux is not automatically an app integration: Android 10+ restricts executing downloaded files from a writable app home. Native packaging must meet [Android's executable-code rules](https://developer.android.com/about/versions/10/behavior-changes-10#execute-permission), rather than adding a download-and-exec workaround.

### Implementation status, 2026-10-18

| Area | Implemented in source | Still required |
| --- | --- | --- |
| Shared Go connection | Shared SOCKS/HTTP lifecycle and managed native launch/cancel/exit handling | Full lifecycle/reconnect device evidence; no wholesale supervisor port |
| Balanced / Fast | Existing Go TCP routes, packet DNS and verified-exit UDP | Xray/ByeDPI/native strategy bundle and device evidence |
| Aether | Packaged core launch, method selection and optional external SOCKS; native scans/reconnect reused | Verified native egress and sustained traffic |
| Tor / Psiphon | Existing Aether backends connected to Android, shared Tor verification and foreign-exit checks | Real egress and sustained traffic; process launch alone is insufficient |
| Windscribe / through Aether | Shared carrier probe exposed to Android | Operational native bridge, catalog/profile integration and authenticated data |
| UDP / DNS | Real SOCKS UDP, wire DoH, DNS over UDP/TCP, no direct UDP fallback | Evaluate native-core packet support before extending Go; public-exit data-plane tests and HEV/TUN validation |
| IPv6 / whole-device VPN | IPv6 packet encoding and platform wiring | Dual-stack public egress, leak tests and device approval gates |
| CDN / ECH tools | Shared four-provider scanner, one-route front/ECH UI, multi-edge Go API | Full CLI tool parity and rendered/device verification |
| MITM / CA | Go implementation preserved, no automatic trust changes | Explicit Android consent/trust flow and optional activation |
| Verification / release | Go checks, ARM bridge package compilation, source checks, official native payload verification and limited x86_64 executable checks | App-UID native execution, JNI/TUN/device/network/battery/reconnect/signing validation; final release remains gated |

### Actual build boundary

The app requires **Android 10 / API 29 or later**, matching HEV 2.19.0. The first real manifest merge rejected the old API 26 setting; no manifest override is used. Local validation produced the real Go bridge for ARMv7, arm64 and x86_64, and built both ARMv7/arm64 and x86_64 debug APKs; the x86_64 candidate was installed on emulator-5554. `-PktestAbis=x86_64` selects emulator packaging; the default ABI set remains ARMv7/arm64. Gradle adds native extraction to the merged manifest through `jniLibs.useLegacyPackaging`. Final native hashes, signatures, device behavior and actual traffic must be verified per candidate.

### Device observations, 2026-10-18

| Check | Observed result | Boundary |
| --- | --- | --- |
| Native Aether/Psiphon launch | Parent and helper ran under the app UID | Process startup, not an authenticated/verified exit |
| User cancellation | Native parent/helper disappeared in about 0.14s; UI returned to Disconnected | One x86_64 emulator |
| Unexpected native exit | Helper reaped, startup error visible, no false connected state | Forced app-owned parent termination before verification |
| Mode change after failure | Previous mode's error no longer reappears | Reproduced before the fix and checked again after it |
| Actual HTTP proxy data | Certificate-verified HTTPS to example.com returned HTTP 200 through the Android HTTP listener | Balanced route through the current system network, not a foreign exit/VPN proof |
| Native Tor verification | Seven-minute budget expired during the neutral HTTPS exit check; no connection was advertised | Does not prove all Tor paths or endpoints are blocked |
| UI | Mode picker, method choice persistence, cancel/error states, navigation, 1.3 font scale and long text input inspected | Emulator input panel observed; full phone keyboard/TalkBack/physical-device acceptance remains open |
| Native ELF preparation | arm64 Go JNI and HEV PT_LOAD alignment both 16 KiB; packaged core hashes verified for ARM and x86_64 APKs | Physical 16 KiB device execution not tested |

No TUN or global network routing was enabled during these checks. Windscribe
modes, remaining desktop strategy/tool parity, live native egress, full packet
routing and final production signing/release remain incomplete.
