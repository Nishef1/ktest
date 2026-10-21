# KTest and PattNG: four-pass final source audit (2026-10-20)

> **Historical snapshot:** this audit records source state and evidence as of 2026-10-20; it is not a claim that the same issues remain unfixed or that the release is now complete.
>
> **Follow-up, 2026-10-21:** Aether is now pinned to v2.3.2 and Xray-core to v26.10.21. The latest reviewed source snapshot passed Go/race/formatting, Android source, Android APK and Windows portable CI. The new current audit tracks the remaining calibration-setting, performance-measurement and physical-device acceptance gaps: [CURRENT_AUDIT_2026-10-21.md](CURRENT_AUDIT_2026-10-21.md). Green CI does not replace the real-world acceptance gates below.

Scope: compare Nishef1/ktest PR #8 with patterniha/PattNG my-releases at 89c760cee27051ac7b6c391d376e528adfdc8a0c and patterniha/Aether at cfc27c50176ee51fd01c1203f4658a0159d24b3b (v2.3.1). These are source and CI findings, NOT evidence of Iranian ISP connectivity. Findings marked fixed are PR changes, not released binaries.

## First independent pass: transport/core and protocol contract

- **P0 fixed:** Desktop Aether mode previously allowed standalone Psiphon/Tor inventory and Tor mode could select non-Tor profiles. Now native mode filtering is explicit: only Balanced mixes backends, Fast and Aether use WARP, Psiphon only Psiphon, Tor only Tor, and Windscribe-Aether only WARP. Tor is now supplied in the default desktop inventory. Shared and desktop unit tests added.
- **P1 fixed:** The prior Aether 2.3.0 command-line flags and newer 2.3.1 options were not equivalent. PR #8 pins the published PattNG-derived Aether v2.3.1 binary/release hashes on Windows, Linux, macOS and Android, adapts renamed API/fragment flags and inspects the final executed profile.
- **P1 fixed:** KTest's optional prefetch of a Cloudflare ECH key was a single point of failure. Two additional MASQUE H2/H3 profiles use Aether's own ECH auto option so the core can attempt an independent key lookup; ordinary non-ECH paths stay present and preferred on Android cold starts.
- **Intentional discrepancy:** PattNG enables quick reconnect for its live profiles; KTest still favors fresh scans unless explicitly configured. Neither approach can be declared better without same-network reconnection measurements.
- **Not ported blindly:** PattNG exposes many knobs (exit-location, TLS fingerprint, DNS, fragments, gateway, nested hops). KTest retains an editable native profile catalog rather than cloning an unrelated UI that increases complexity.

## Second independent pass: Windscribe and website data planes

- **P1 fixed:** Blocked mob-v2 APIs could delay valid Windscribe fallback catalog discovery. A bounded hedged legacy request can now publish the first validated exact-node mapping.
- **P1 fixed:** One failed provider list was previously enough to cause repeated multi-source re-downloads. A partial valid refresh is usable; missing exact target nodes get bounded faster retries.
- **P1 fixed:** Direct Windscribe WStunnel now includes the standard Go TLS baseline, Chrome uTLS and explicitly named randomized uTLS, plus a no-custom-SNI baseline. A real local TLS WebSocket server round-trip tests framing and byte preservation.
- **Known fundamental gap:** The HTTP CONNECT bridge is for installed Windows Windscribe OpenVPN TCP, not a substitute for UDP WireGuard, IKEv2 or OpenVPN UDP support. Neither an HTTP 101, a valid TLS record nor a server-shaped OpenVPN packet proves authenticated Windscribe connectivity or exit geography. No all-country/all-protocol claim is supported.
- **MITM/CDN constraints:** Website fronting needs a compatible actual edge and application CA trust; an owner-configured CDN path needs real origin routing. A fake SNI alone is not arbitrary CDN domain fronting. Strict foreign-only protection must remain intact.

## Third independent pass: Android, DNS, keys and lifecycle

- **P1 fixed:** Parallel Balanced Android workers could provision independent first-use WARP identities into the same saved MASQUE/WG path. A single cold-enrollment gate now prevents that race while preserving warm parallel probes and non-WARP alternatives; concurrent regression test added.
- **P1 fixed earlier:** Android Aether Auto now tries independent WARP transport families; filtered ECH lookups do not erase non-ECH fallback methods. Strict foreign HTTPS/IP checks remain distinct from SOCKS listener readiness.
- **Correct already:** KTestVpnService excludes its own package from the Android TUN route, avoiding native-proxy recursion. KTest already owns independent Xray/HEV adapters, packet DNS and Go route selection; PattNG instead makes Xray primary and Aether a SOCKS outbound.
- **Incomplete:** PattNG stages and recovers explicit key renewal more comprehensively than the current KTest Android UI. Android on-device TUN UDP/IPv6/DNS, Wi-Fi to cellular handover and third-party Windscribe VPN coexistence still require physical testing. Do not auto-delete valid/refused identities.

## Fourth independent pass: builds, resource use, dead code and truthfulness

- **P0 fixed in build process:** Source-only Android CI was unable to certify APK integration. PR #8 adds an unprivileged Android build smoke workflow: compile actual Go JNI, prepare checksum-pinned native binaries, compile Kotlin APK, and inspect packaged binary SHA-256. It does not expose signing credentials, publish an APK or prove an ISP connection.
- **Code cleanup:** A reachability audit was run. Four demonstrably unused internal helpers were removed. Exported gomobile entry points and OS build-tag stubs were retained because a Go-only dead-code analyzer cannot see Android/Kotlin consumers.
- **Resource boundary:** Windscribe per-CONNECT racing and replay buffers are bounded, but their limits are heuristics rather than measured optimal concurrency. Lower overhead and greater success need controlled matched-network A/B measurements.
- **Release gate:** Check the latest PR head SHA for tests/race/formatting/Android build status; do not cite an earlier successful commit as proof of later code. Keep PR draft and do not merge/release without required gates.

## Required real-world acceptance

1. Same ISP, time, gateway and profile: run the same pinned Aether v2.3.1 in PattNG and KTest; separately log core launch, SOCKS, WARP CONNECT-IP, HTTPS payload and foreign exit.
2. Same Windscribe client, node, port and protocol: compare native TCP, WStunnel Go TLS, Chrome/randomized variants, Stealth and properly configured owned CDN. Require Windscribe Connected, independent IP/country and continuous data.
3. Separately validate UDP-capable Windscribe integration; no TCP-only result substitutes for WG/IKEv2/OpenVPN UDP.
4. On a physical Android phone: test Xray/HEV TUN switching, DNS leaks, UDP/IPv6, disconnect, network handover and identity persistence. Verify the VPN app itself is never captured by its TUN.
5. Confirm current-head Go CI, a full Android APK compile+digest verification, Windows portable build and third-party license notices.

**Decision:** Keep KTest's own Go smart routing, Windows Windscribe interoperability, ByeDPI and network diagnostics. Reuse the source-aligned, checksum-pinned Aether transport from PattNG and adopt its disciplined identity/process handling. Do not claim universal censorship bypass or that every Windscribe country/protocol now connects.