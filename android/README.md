# KTest Connection for Android — active development (no new APK builds)

## Reference-driven native integration (work in progress)

Source integration now includes the Guardian Project `tor-android:0.4.9.14` and `jtorctl:0.4.5.7`, bound to the KTest foreground proxy service. A Tor circuit must be established and a Tor exit verified through Go before using the Tor proxy. A bounded watchdog stops proxy listeners if Tor repeatedly becomes unavailable. **No Android device compile/runtime test was performed for these changes.**

An experimental `VpnService` + HEV adapter is also added. It can only start with an **external**, loopback, UDP-capable SOCKS5 listener from an explicitly named installed app package. It checks verified foreign egress and an actual SOCKS UDP DNS response before establishing the TUN, and marks the result `TUN ACTIVE / UNVERIFIED` rather than Connected. Direct Tor/SOCKS and the existing TCP-only Go proxy are not eligible for this HEV mode. Upstream HEV 2.19.0 AAR is fetched by the version-pinned and SHA-256-pinned `android/scripts/fetch-hev-aar.sh` **during a manual build only**.



**Scope:** an English-only Jetpack Compose client with a real Go SOCKS5 + HTTP proxy service, bounded network diagnostics, CDN/ECH research tools and user-initiated official-update checks. It is **not** a system VPN and it does not embed Aether, Psiphon or Tor cores.

## Current development gate (2026-10-17)

Do **not** generate new APK/AAR artifacts after every commit. The Android workflow is manual-only (`workflow_dispatch`) until the owner explicitly approves a release candidate. The ordinary Go quality/test workflow remains enabled.

This branch has new in-progress changes beyond the last Android preview. Version labels in source control and existing preview APKs must not be treated as evidence that these changes are installed or device-tested.

## New development: HEV / VPN UDP preflight

- `mobilebridge.CheckUDPRelay(address)` performs a real SOCKS5 UDP ASSOCIATE handshake **and** a fresh `example.com` DNS query to 1.1.1.1 through the local relay. A successful TCP/SOCKS reply alone is insufficient.
- It refuses SOCKS listeners outside loopback and refuses UDP relay addresses outside loopback; no arbitrary remote UDP endpoint is dialed.
- The advanced Tools screen exposes this independent test and explicitly says that it does **not** start or verify a VPN. The check only indicates UDP transport availability; it does not establish exit anonymity, foreign IP, IPv6 support, DNS privacy, or process recovery.
- External Aether, Tor and Psiphon proxy modes now apply `ExitOnly` to **every** host, not only known AI destinations, so they require verified foreign egress on revalidation instead of silently falling back to direct.
- The Power Orb's infinite visual pulse is active only while the proxy is running, not while idle.

Detailed safety decisions and the integration gate are in [docs/ANDROID_VPN_SECURITY.md](../docs/ANDROID_VPN_SECURITY.md).

## Current capabilities

| Mode | Android implementation | Meaning of success |
| --- | --- | --- |
| Balanced | Existing Go plain + TLS ClientHello-splitting paths; optional separately running SOCKS5 foreign exit | Local proxy started; use the "Verify real HTTPS traffic" control to check actual sites |
| Fast | Same Go paths, shorter hedge delay; optional separately running foreign SOCKS5 | Same limitations as Balanced |
| Aether | Requires user-supplied local SOCKS5 listener from a separately running compatible Aether installation | An HTTPS Cloudflare trace passed through configured proxy and reported a country other than IR/RU; **does not verify WARP/MASQUE transport** |
| Psiphon | Requires a separately running Psiphon SOCKS5 listener; not built into KTest | Same HTTPS egress requirement; **does not prove Psiphon's own server authentication or transport** |
| Tor | Requires a separately running Tor SOCKS5 listener; not built into KTest | Both HTTPS egress and official Tor Project API `IsTor` checks passed |
| Windscribe / Windscribe+Aether | Not implemented on Android | Disabled; no fabricated "connected" indicator |
| CDN fronting | Controlled test using existing `internal/edges` + `internal/probe`, one numeric edge IP, explicit TLS SNI/Host | Reports `http_2xx_unverified`, `tls_only`, etc.; no origin claim without challenge proof |
| ECH | Existing `internal/front.FetchCloudflareECH` accessed from Tools | ECH retry configuration fetched, **not** a working tunnel |

External SOCKS entry is **loopback-only**, with a strict port validation, system TLS verification, bounded HTTPS validation and no direct fallback for the single-upstream modes. Protected known AI hostnames remain fail-closed without a verified foreign exit, but not all raw-IP/unknown-domain traffic can be attributed; do not claim an identity kill switch.

External upstream validation depends on an HTTPS Cloudflare trace that supplies a public egress IP and non-IR/RU `loc` value. This is an *observed egress check*, not cryptographic geolocation attestation. Geographic classifications, shared networks and censorship change. Tor additionally requires HTTPS confirmation from Tor Project's `check.torproject.org/api/ip`. No app could guarantee the success of such checks on every ISP.

### Usage

1. Pick Balanced/Fast or select Aether/Psiphon/Tor.
2. For Aether/Psiphon/Tor, start the compatible external core **first** and enter its actual local SOCKS5 port (e.g. `127.0.0.1:9050` only if that is really where it listens). Aether/Psiphon/Tor are not bundled.
3. Tap Connect. On foreign-core modes this validates HTTPS egress **before** activating a local proxy. The status is **PROXY ACTIVE**, not `VPN Connected`.
4. An application which supports proxies must explicitly use the displayed local SOCKS5 or HTTP address. Tap "Verify real HTTPS traffic" to check representative destinations.
5. Disconnect from the main Power control or foreground notification. Listener port and mode persist only for that session.

### Limitations and required future work

* The app does **not** use `VpnService`, HEV, TUN or UDP. Most ordinary Android apps will not use a local SOCKS5 proxy automatically.
* External Tor/ Psiphon / Aether modes require the corresponding third-party core or instance. Aether may itself be a VPN, which cannot run alongside a second active Android `VpnService` in the same user profile.
* Full embedded Psiphon requires the upstream official Android AAR and valid sponsor/channel/server-list configuration; it also has GPL-3.0 licensing implications. No credentials are invented.
* Embedding Tor requires packaging a maintained Tor engine and testing bridge/bootstrap and circuit isolation. Reaching `9050` alone is not a Tor proof.
* Native Aether requires Android-compatible Zeptun and transport configuration. The Windows external-binary launcher is not portable.
* Domain fronting is not an arbitrary-free relay. Provider policies vary (CloudFront can return 421), and real MITM/CA modes need **explicit opt-in**, secure on-device key handling and upstream certificate validation. Existing Go `internal/front` CA functionality is preserved but **not activated** in this APK.
* Background status and foreground service require testing across OEM battery policies, process death, and connectivity changes.
* Release updates require a stable developer-owned signing key; GitHub CI preview Debug signing is NOT update-compatible across runs. The artifact is a ZIP containing an APK and must be extracted.

### Technical build

Go version from root `go.mod`, SDK 36, NDK r28c, Java 17+, Gradle 9.5+; `gomobile bind -target=android/arm,android/arm64 -androidapi=26`. CI executes Go tests, builds native AAR, compiles Kotlin/Compose APK, validates signature and both ABIs, and uploads preview. This establishes build correctness, not on-device connectivity.

### Verification gates before a release claim

- [ ] Physical ARM32/ARM64 install, foreground/notification/rotation/background.
- [ ] Native core startup and shutdown, concurrent rapid taps and stale state.
- [ ] Proxy HTTPS smoke tests and TLS certificate verification on Android 8–16.
- [ ] Aether / Psiphon / Tor upstreams with independently supplied valid endpoints and protected-site fail-closed checks.
- [ ] Network change and DNS/IPv6 leakage tests.
- [ ] Real CDN origin challenge verification on an operator-owned test endpoint.
- [ ] HEV + `VpnService.protect` + UDP-aware upstream design and complete routing validation.
- [ ] Stable release signing and OTA upgrade compatibility.
