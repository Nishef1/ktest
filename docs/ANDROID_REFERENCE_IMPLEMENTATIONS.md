# Android cross-project implementation review (October 2026)

This is based on **inspected repository source**, not claims of equivalent functionality in KTest and not tests on an Iranian ISP. KTest continues to use Go for its core and Kotlin for its Android app. No APK or distributable binary should be generated until the user explicitly requests a full release candidate.

## Projects inspected

| Source | Evidence | Reusable pattern | Constraint / decision for KTest |
| --- | --- | --- | --- |
| [Aether Mobile](https://github.com/QW-AI-Code/Aether) | `app/src/main/java/studio/cluvex/aether/vpn/AetherVpnService.kt`, `core/HevTunnel.kt`, `core/TunnelConfig.kt`, `model/ConnectionState.kt` | Internal engine -> local SOCKS5 -> HEV -> Android TUN; verify **after** the service starts and before displaying "Connected"; handle revocation and engine death | Licensed AGPL-3.0. Our source implements its own lifecycle rather than copying it. That app embeds a Rust engine, not a Go replacement for KTest. |
| [Shir-o-Khorshid](https://github.com/shirokhorshid/shirokhorshid-android) | `app/src/main/java/com/psiphon3/psiphonlibrary/TunnelManager.java`, `TunnelVpnService.java` | Psiphon has a real Android lifecycle, revocation handler, transport selection, foreground status, state messages and underlying tun2socks | GPL-3.0. Several sponsor, propagation, key and distribution settings must be provisioned legitimately; we have not taken/guessed them. |
| [MahsaNG](https://github.com/GFW-knocker/MahsaNG) | `V2rayNG/app/src/main/kotlin/com/v2ray/ang/service/V2RayVpnService.kt`, `gfwknocker/TLS_Fragmentor.kt`, `DoH_over_Fragment.kt` | Reference for native VPN boundaries, TLS fragmentation, DNS transport and per-app routing | GPL-3.0. README states some authentication/config code is closed, and the public tree cannot build the complete service standalone. Do not adopt advertised connections without complete usable server configuration. |
| [Se7en-Pro](https://github.com/KNG7-P/Se7en-Pro) | `Se7enPro/Services/LocalSocksEngineBase.cs`, `SocksProbe.cs`, `Tun/SocksDnsForwarder.*.cs`, `README.md` | Route validation, DNS-over-SOCKS tests, configuration and engine integrity separation | Windows/C# program, not an Android VPN implementation. Source MIT but Psiphon and Xray binary licensing differs; it explicitly excludes usable Psiphon sponsor/server configurations. |

## Changes inspired by the inspection

- Added version- and SHA-256-pinned HEV AAR preparation script for **manual builds only**. Upstream official release: `heiher/hev-socks5-tunnel` 2.19.0, GitHub asset SHA-256 `fbbf014c1c4c6d1e0922db88542abd9dc726600473bdfdc8039ed157b4ba02b0`.
- Added a separate `KTestVpnService` that establishes an Android VPN only after opt-in consent, verified foreign TCP egress, and a successful **UDP/DNS** roundtrip through a *local*, *separately running* SOCKS5 server.
- The VPN's TUN default routes include IPv4 and IPv6; its DNS resolvers are routed through that TUN. Native HEV must start successfully; its failure tears down the interface. Only KTest and the explicitly named **upstream app** are excluded from routing so their sockets cannot recurse through the VPN. This exclusion is a privacy tradeoff: the upstream app's own other connections also bypass this VPN.
- Even with TUN/HEV running, the app reports `TUN ACTIVE / UNVERIFIED`, never an unearned "Connected" status. Full-device app traffic and leak testing remain outstanding.
- Added in-app embedded Guardian Project Tor library `tor-android:0.4.9.14` and its `jtorctl` companion `0.4.5.7`, sourced from Guardian's verified Maven repository. Tor bootstrap requires a **circuit-established** control signal and a *separate* HTTPS exit verification by KTest's Go core. Note this is source-integrated and **not yet device-validated**.
- Tor SOCKS5 supports **TCP**, not SOCKS5 UDP. Therefore it is allowed for **proxy mode only**; a working all-device Tor VPN would require a front end translating at least DNS to TCP and deliberately handling other UDP, or a different suitable native tun stack.
- Existing Go Domain Fronting/ECH and MITM/CA source code is preserved, without silently installing any device certificate. It does not supply an unrestricted foreign network exit.

## Not solved yet

1. **Psiphon bundled**: legitimate sponsor/channel/server-list configuration, licensing review and actual Android AAR lifecycle. Shir-o-Khorshid confirms this cannot be substituted with empty placeholders.
2. **Aether bundled**: inspect/obtain buildable native Android engine source for the intended Zeptun/Aether version, pinned ABIs, credentials as required, and safe lifecycle. Calling any SOCKS port "Aether" does not prove MASQUE/WARP.
3. **Balanced/Fast VPN**: built-in Go SOCKS server is CONNECT/TCP only, hence does not pass its own UDP preflight. Do not claim it drives HEV full-device routing until it supports UDP or is behind a separate validated UDP-capable transport.
4. **Tor full-device VPN**: an explicit UDP/DNS-over-TCP bridge, transport lifecycle and leak validation still needed.
5. **Battery/quality**: on-device A/B tests against sing-box, modem handover, background/foreground process lifecycle, Android's always-on/lockdown rules, and IPv6/DNS/WebRTC leak tests. No CI source test can replace these.
6. **Modern UX**: deep design review across smaller phones, large accessibility fonts and TalkBack is still required. English-only UI and animated power control are already in source.

## Strict user request

No automatic APK/AAR/desktop artifact publishing from this feature branch. `.github/workflows/android-build.yml` remains manual-only; shared `.github/workflows/ci.yml` still runs unit/race/vet tests but skips binary upload jobs on non-main branches. This step did **not** trigger the manual Android APK workflow.
