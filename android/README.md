# KTest Connection · Android (in development)

**No Android APK is produced automatically.** The release workflow uses `workflow_dispatch` only. Work on this branch runs **Go tests, vet, formatting and race tests**, not a generated installation artifact. There has been **no Android compilation or physical-device validation** for the latest Tor/HEV changes. Do not market this branch as a completed VPN.

## Implementation status (as of 2026-10-17)

| Mode / feature | In source | Fully verified on Android |
| --- | --- | --- |
| Balanced & Fast proxy | Existing Go SOCKS5 with plain / TLS ClientHello splitting, adaptive routes; optional external foreign SOCKS5 | No; desktop-Go unit tests only |
| Embedded Tor proxy | Guardian Project Android Tor AAR `0.4.9.14`, Tor service binding, circuit bootstrap, Tor Project HTTPS egress verification, watchdog and stop | No |
| Aether | User-supplied **separate** local SOCKS5 server with verified foreign egress; does not bundle Zeptun/Aether | No |
| Psiphon | User-supplied **separate** local SOCKS5 server with verified foreign egress; no bundled Psiphon core/configuration | No |
| Windscribe / Windscribe + Aether | Visible but disabled, as their required Android core orchestration is absent | No |
| CDN fronting / ECH | Existing Go diagnostic probes; controlled proof is needed to claim origin routing | No production transport |
| Experimental Android VPN | Kotlin `VpnService` + pinned upstream HEV `2.19.0`, external loopback SOCKS5 TCP/UDP preflight, TUN state, stop/revoke, best-effort TUN blackhole | **No** |
| MITM / CA | Existing opt-in desktop Go source is preserved; **no certificate is installed on Android** | No |

**Scope:** English-only Jetpack Compose interface; large Power control; local SOCKS5/HTTP addresses; network diagnostic tools; manual release check. A successful Go/Java listener or a green TUN status is not proof that another app's traffic reached an uncensored foreign network.

## Why Tor and Psiphon need different work

Tor's local SOCKS5 is **TCP-only** and cannot directly satisfy HEV's UDP ASSOCIATE for all device traffic. A DNS-over-TCP adapter and deliberately specified behavior for non-DNS UDP are prerequisites for Tor's whole-device VPN. We do not fake UDP capability.

The official Psiphon Android library is a Go-based AAR, and it loads `gojni`. KTest already uses a separate `gomobile` AAR that also packages `libgojni.so`. Installing both unchanged risks a collision between distinct Go runtime/native library builds. We must either consolidate the Go libraries into one build or isolate and rename the Psiphon native runtime in another Android process, with explicit IPC and verified packaging. Legitimate sponsor, channel and server-list configuration is necessary; placeholder IDs are not usable.

Aether requires a reproducible Android Zeptun/Aether native core, lifecycle management and verified MASQUE/WARP configuration. Attaching an arbitrary local SOCKS5 service does not prove Aether is running. Windscribe on Android often owns the single available `VpnService`, so it cannot simply be stacked beside another active VPN.

## Safety gates in current experimental VPN

1. Android permission is explicitly requested through `VpnService.prepare()`.
2. A **separately running**, IPv4 loopback-only SOCKS5 endpoint and the real package name that owns it are required. The service first requires a TLS-verified HTTPS request with a non-IR/RU egress observation.
3. SOCKS5 UDP ASSOCIATE must **actually return a valid DNS answer**, not just an accepted command. The reported UDP source must match the requested DNS address/port. The current Go-built proxy is CONNECT/TCP-only and is **not eligible**.
4. The VPN builder routes IPv4/IPv6 through the TUN, advertises matching DNS and excludes only KTest plus the separately identified SOCKS provider's app UID to prevent routing loops. The excluded apps themselves bypass this VPN; Android's per-profile single-VPN rule still applies.
5. HEV's JNI startup must report success. UI shows `TUN ACTIVE / UNVERIFIED`; it does not show `Connected` until actual routed app traffic is validated.
6. Native death or the **first failed periodic foreign-exit recheck** enters a best-effort TUN-blocking state. It is not an OS-grade kill switch. Users who need protection against Android force-stop/process death must configure Android's **Always-on VPN / Block connections without VPN**.
7. Manual Disconnect, service destruction and Android `onRevoke()` stop HEV, release the TUN and cancel pending startup.
8. The integration still requires testing in real dual-stack networks, DNS leaks, 4G/5G ↔ Wi-Fi transitions, Doze, foreground services, IPv6 UDP, captive portals and device OEM battery restrictions.

## Source dependencies / licensing

- Go core: `github.com/Nishef1/ktest` and native AAR generated from the **same source**; no Rust migration.
- HEV: pinned release `2.19.0`, upstream SHA-256 `fbbf014c1c4c6d1e0922db88542abd9dc726600473bdfdc8039ed157b4ba02b0`. Source-only preparation: `android/scripts/fetch-hev-aar.sh`. It runs only during an explicitly approved manual build.
- Tor: `info.guardianproject:tor-android:0.4.9.14` and `info.guardianproject:jtorctl:0.4.5.7`, Guardian Project Maven repository; check app and native licenses before distributing.
- Shir-o-Khorshid and MahsaNG GPL-3.0; Aether AGPL-3.0; Se7en Pro MIT. Reference designs were inspected, not silently copied into KTest.

Supporting rationale: [Android VPN security gates](../docs/ANDROID_VPN_SECURITY.md) and [source-project comparison](../docs/ANDROID_REFERENCE_IMPLEMENTATIONS.md).

## Development and release gates

The source tests run on pushes (`go test ./...`, `go test -race ./...`, `go vet ./...`). They **cannot** validate Android-native JNI, Gradle dependency resolution, installation, UI usability or real connection to filtered networks. Only after all native integrations are implemented should the owner authorize **one controlled compilation and device validation**; do not upload debug-signed previews for every commit. A stable owner-controlled release signing key and tested upgrade path are mandatory before public distribution.

Next required source milestones: fix cross-core Android networking, implement a verified Tor DNS/UDP bridge (or explicitly block unsupported UDP), integrate legitimately configured Psiphon without `gojni` collisions, integrate reproducible Aether/Zeptun, then audit and test the native VPN lifecycle and UI. No completion guarantee can be given before those tests.
