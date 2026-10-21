# KTest Android — existing native cores with shared Go integration

Android uses the **existing upstream networking cores**, a narrow shared Go integration layer and a native UI. Aether owns MASQUE/WireGuard, native gateway scans/reconnect and its Tor/Psiphon backends. Xray, ByeDPI and Windscribe retain their respective roles. Do not reimplement these engines in Go or Kotlin, or port the entire CLI supervisor as an Android prerequisite. The [engineering roadmap](../docs/ROADMAP.md) records responsibility boundaries, remaining work and the code reuse audit.

Keep Go for required KTest policy, lifecycle, shared diagnostics and existing mixed-mode routing. Prefer the selected core's native SOCKS/HTTP and packet capabilities where they satisfy the mode contract; an additional Go proxy is not a universal requirement. Any simplified path must preserve verified-exit checks, expiry and fail-closed routing.

## Single-source architecture

- `cmd/ktest`: original CLI and its platform-dependent orchestrators.
- `internal/smartproxy`: shared Go adaptive TCP/SOCKS engine and RFC 1928 UDP ASSOCIATE. Non-DNS datagrams require a verified foreign loopback transport with a working UDP relay (in Aether, also the working WARP carrier for destinations known to be ordinary; see docs/CONNECTION_MODES.md), and never fall back to a direct UDP socket.
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
| Balanced | Go direct/ClientHello routes plus the original packaged ByeDPI and shared desktop strategy catalog |
| Fast | Same native/local routes with the shared Fast policy |
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

**Whole-device VPN is the default coverage (beta).** Connect asks for Android VPN consent and starts the selected Go proxy. After proxy startup and any required strict-exit verification, `KTestVpnService` passes Android's TUN fd to the Go core. Go tries the checksum-pinned Xray TUN inbound first; Xray receives the fd through `XRAY_TUN_FD` and sends every flow to the local Go SOCKS listener. Xray is only the packet adapter, not an independent exit: adaptive route selection, DNS policy, fronting, verified foreign exits and UDP leak prevention remain in Go. If Xray is missing, unsupported, fails startup or exits later, Go automatically switches to HEV on the same Android TUN fd. The active packet engine and fallback reason appear in Settings. The user does not need to select or retry these adapters manually.

"Proxy apps only" remains a choice. IPv6 is routed into the TUN only when the underlying network has a global IPv6 address and default route; otherwise Android carries no v6 route, so apps use IPv4. DNS goes through the Go packet-DNS path; other UDP (e.g. QUIC) is relayed only via a verified foreign SOCKS5 UDP association (Aether: also its working WARP carrier, for destinations whose names are known and not protected) and is otherwise dropped. Address-only ECH connections are routed by the names Go's packet DNS resolved to that address and fail closed onto the foreign exit when none is known. Apps may fall back to TCP, but whether and how quickly that happens is client-dependent. The service polls Go and tears the TUN down if the proxy or both packet adapters stop. Xray TUN support is upstream's layer-3-to-layer-7 proxy, not a native IP tunnel; its startup and process liveness are not proof that every destination is reachable. Physical-device, leak, roaming and battery validation are still open.

The KTest app UID is excluded from the TUN while the Xray/HEV packet dataplane is active, to prevent upstream feedback loops. As Android documents, that app's own networking is then outside its VPN coverage; user's other apps remain in its routing scope. Alternative `protect(fd)` per Go socket may be evaluated when the Go core's Dialer can support it.

**Separate-UID device acceptance probe:** the non-release `:vpnprobe` module is intentionally a different Android package from KTest, so its own requests are not excluded by the VPN builder. Build it from the repository root with `./android/gradlew -p android :vpnprobe:assembleDebug` (Windows: `.\android\gradlew.bat -p android :vpnprobe:assembleDebug`), install `android/vpnprobe/build/outputs/apk/debug/vpnprobe-debug.apk`, connect KTest System VPN, then open **KTest VPN Probe**. Run the checks once without KTest VPN and again with it. The probe tests system DNS, an explicit DNS-over-UDP packet, certificate-verified HTTPS, IPv6 HTTPS when the active VPN exposes an IPv6 default route, and a STUN UDP request. Results remain local. A pass verifies only that specific destination/protocol; a failure may be destination- or ISP-specific and should be compared with the no-VPN baseline. This is the required end-to-end check because a live Xray/HEV process alone cannot prove that packets reach the Internet.

## Retained functionality

- Shared Go proxy mode routing, bounded foreign-exit checking and app-facing SOCKS5/HTTP proxy. Both Balanced and Fast connect immediately with adaptive routing and no automatic calibration or frozen targets. Offline route tests are optional diagnostics; see [route calibration and evidence boundaries](../docs/ANDROID_ROUTE_CALIBRATION.md).
- Network DNS/TCP/TLS diagnostics, CDN fronting and ECH tests provided by existing Go packages.
- Local CA generation and optional fronting reuse Go. Installation into Android's user trust store requires explicit user action; the private key stays in app-private storage, and native-app trust is not guaranteed.
- English dark UI: animated power control with phase steps (prepare / start core / verify exit), session uptime, copyable SOCKS5/HTTP endpoints and per-target HTTPS verification; Tools as collapsible cards; Settings with manual update checks, packaged-core hash verification (`InspectAndroidBundle`), privacy notes and open-source notices for the shipped AGPL/GPL/BSD/MIT executables. Adaptive launcher icon, monochrome notification icon with a session chronometer.
- Diagnose can select automatic TCP, IPv4 or IPv6; connection startup exposes its verification phase and supports cancellation/reconnect.
- CDN scan uses the shared Cloudflare/Akamai/Fastly/Google candidate policy and TCP/TLS/HTTP scanner. Finite scans consume the chosen candidate budget unless canceled or the real inventory ends; there is no ten-success cap. Slider maximum passes budget `0`, continuing until manual cancellation or source exhaustion without a session deadline. Cloudflare iterates only its known official ranges; other providers exhaust their source-backed pool. All started attempts and measurements stream to a private CSV snapshot for export through Android's save picker; UI results stay bounded. Provider HTTPS is not arbitrary-fronting or native-app evidence.
- Windscribe carrier testing uses the shared Go WStunnel/Stealth probe for one explicit entry and certificate-valid hostname. This does not implement the desktop node catalog/SNI comparison, OpenVPN authentication, official app integration or an operational Windscribe VPN.
- Target front/ECH diagnostics derive an existing family strategy and preserve the target's HTTP Host. The low-level `TestFronts` API also remains available for 1..12 explicit edges, 1..3 rounds and optional controlled-origin proof. Provider-HTTPS verified scan edges are only candidates until the actual target is validated.

## DNS is an observed path, not an availability guarantee

DoH, DoT, ECH, resolver IPs, TLS names and carrier protocols can be filtered independently. This app does not assume that encrypted DNS works in Iran, and does not implement a DoT fallback. Wire DoH tries bounded independent endpoints with hedging; a silent first endpoint does not consume the whole budget before alternatives begin. Strict modes send these requests through their verified SOCKS exit and never enable direct ECH/system DNS as an escape from that policy. Balanced/Fast's existing hostname resolver can use the system-first trusted-resolver policy; **packet DNS** has no plaintext fallback.

Lightweight session diagnostics report TCP result counts, TLS replies, UDP associations, UDP/443 failures and the last selected route with its timing. No destination names, response bodies, tokens or cookies are saved in these counters. Their values cannot by themselves prove an X app uses QUIC or identify the cause of an HEV/Xray delay.

Balanced/Fast watches the default Android network handle during connection. On handover, KTest debounces the replacement network, tears down the old Go/TUN session, waits for Android to close the previous VPN interface, and automatically restarts the same mode on the new network. If no stable replacement appears within 20 seconds, or the old VPN cannot shut down cleanly, it stops with an explicit error instead of silently claiming recovery. Real-device roaming tests are still required.

Packet DNS failures appear separately in proxy status and the connection screen. They are transport observations, not proof that the Internet, destination, or all DNS methods are unavailable. In-country availability and censorship causes still need measurements. See [network diagnosis](../docs/NETWORK_DIAGNOSIS.md).

## Source verification without APK/AAR output

`bash android/scripts/check-sources.sh` generates the actual gomobile Java API, then compiles Kotlin against the unchanged checksum-pinned HEV 2.19.0 AAR and merges its actual manifest in a temporary copy. It requires Linux, Go, JDK 17+, Android platform 36 and Gradle 9.5.0. It leaves `go.mod`/`go.sum` unchanged and builds **no native libraries, AARs or APKs**; the existing HEV AAR is downloaded and verified, not rebuilt. Go CI includes this source check and formatting of `mobilebridge`.

Passing it establishes Java/Kotlin source compatibility, including callback signatures. It does not establish native linkage, JNI loading, rendered UI, device traffic, leaks, battery use or reconnect on a phone. Production release publication remains separate from preview Actions artifacts.

## Stable preview signing and updates

The preview revision is version code **19**, version name **0.4.7-preview**, with application ID `com.nishef.ktest`. Preview Actions builds use a dedicated, stable PKCS12 signing key; they remain debug build variants for internal testing, not production releases. The signing key is separate from the app's local MITM CA key.

The repository owner provisions the preview signer outside the repository with [`android/scripts/provision-preview-signing.ps1`](scripts/provision-preview-signing.ps1). Its local state is under `%LOCALAPPDATA%/KTest/preview-signing`, with DPAPI-protected password storage; the PKCS12 alias is `ktest-preview`. Consult that script for its options. Do not commit the keystore/passwords or use a CI-generated replacement key. Key provisioning and secret updates are explicit owner actions, not part of the build workflow.

The workflow requires all five repository secrets before checkout, SDK installation, Go binding, or native packaging:

| Repository secret | Use |
| --- | --- |
| `KTEST_PREVIEW_KEYSTORE_BASE64` | Base64-encoded dedicated preview PKCS12 keystore |
| `KTEST_PREVIEW_KEYSTORE_PASSWORD` | Keystore password |
| `KTEST_PREVIEW_KEY_ALIAS` | Preview signing alias (`ktest-preview` for the provisioner) |
| `KTEST_PREVIEW_KEY_PASSWORD` | Signing key password |
| `KTEST_PREVIEW_CERT_SHA256` | Expected signing certificate SHA-256 fingerprint; colon separators and letter case are normalized |

CI decodes the keystore into a private runner-temporary directory under `umask 077`, passes its filename as `KTEST_PREVIEW_KEYSTORE_PATH`, and supplies the password/alias variables to Gradle through its environment. `KTEST_REQUIRE_PREVIEW_SIGNING=true` prevents fallback to a developer debug key in that step. The APK is verified with `apksigner verify --print-certs` and its actual certificate must match the expected fingerprint before artifact upload. Secret values and certificate reports are not printed. An always-run cleanup step removes the temporary signer; no keystore is included in artifacts. See Android's [signing configuration](https://developer.android.com/build/build-variants#signing) and [APK signature verification](https://developer.android.com/tools/apksigner) references.

Local developers can keep the existing default debug signing by leaving the preview variables unset. To use the stable signer locally, provide `KTEST_PREVIEW_KEYSTORE_PATH`, `KTEST_PREVIEW_KEYSTORE_PASSWORD`, `KTEST_PREVIEW_KEY_ALIAS`, and `KTEST_PREVIEW_KEY_PASSWORD` in the build environment. All four must be present, and the path must point to an existing absolute PKCS12 file. Partial configuration fails instead of silently selecting another key. Avoid logging environments or passing passwords on command lines.

Android accepts in-place updates when the application ID and signing identity match and the version is acceptable. Installing such an update (`adb -s <device-serial> install -r <preview.apk>`, or the Android package installer) retains app-private data, including the local CA certificate/private key and saved configuration. **Do not uninstall merely to update.** A full uninstall or Clear storage removes the app-private CA key; an Android user trust-store certificate may remain and cannot recover the deleted private key.

An older APK signed with a runner-generated random debug key cannot be updated in place by this new signer. It needs a one-time uninstall/reinstall migration after the user accepts losing app-private state. Remove any obsolete Android user CA entry, generate a new local CA after migration, and install its public certificate again only if optional fronting is desired. Do not export the MITM private key to migrate it. Future previews must keep the same dedicated signer to avoid repeating that migration. Stable signing enables data-preserving updates; retention and trust behavior for this candidate still require phone verification.

## Aether / Tor / Psiphon upstream provenance and trust boundary

- The Android package uses the **checksum-pinned `patterniha/Aether` v2.3.2 release archives**, not independently downloaded Psiphon or Tor binaries. Exact archive SHA-256 values are pinned in `internal/aether/android-cores.json`, and the unmodified executable SHA-256 values are checked both by the Android packager and at runtime by `AndroidBundlePaths`.
- `libaether.so` contains the **Arti** Tor implementation, built by upstream with Cargo feature `tor`. Standalone Tor uses Aether's `--tor-only`; neither the Go app nor Kotlin includes a second Tor implementation. The extracted `liblyrebird.so` provides Tor pluggable-transport support; `ProfileArgs` explicitly passes its package path through `--tor-pt` and an app-private `--tor-dir`.
- `libpsiphon-tunnel-core.so` is the **console-client helper from the `CluvexStudio/psiphon-tunnel-core` fork** selected by Aether v2.3.0's `psiphon-build.sh`. That script names `shirokhorshid` and source commit `83aa73b9b982e7421e00117f5b0c5aceb5dda452`. `ProfileArgs` passes the pinned APK helper path with `--psiphon-bin` and the private `--psiphon-dir`. This is not a separately selected Psiphon Android SDK.
- **Source provenance limitation:** the upstream `psiphon-build.sh` explicitly falls back to the current branch when checkout of the pinned commit fails; `pt-build.sh` can similarly fall back to the Lyrebird repository default branch. Thus the release archives' known hashes establish **artifact identity**, not reproducible proof that every ABI was built at those source commits. A self-built replacement must remove these fallback paths and lock all inputs before making that stronger claim.
- Selection and verification are distinct: Tor requires an authenticated Tor egress check; Psiphon and Aether require a verified foreign exit. A native process launch, SOCKS listener, UI `Auto`, or VPN adapter does not by itself prove any of these. Android `Auto` currently chooses the *first compatible profile*, then the Aether core handles native gateway selection; it does **not** compare multiple Aether methods in parallel. The UI describes that explicitly.
- Android still needs device/ISP-based checks for sustained Tor, Psiphon and Aether traffic, native-helper crashes, reconnect and resource usage. Neither the APK hashes nor desktop CI prove this.

## Xray 26.10.10 TUN + HEV fallback: distinct responsibilities (ARMv8)

- KTest retains pinned HEV 2.19.0 as a fallback adapter. When whole-device VPN coverage is enabled, Go first launches the official Xray TUN inbound using Android's existing `VpnService` fd via `XRAY_TUN_FD`. Xray's only outbound is the local Go SOCKS listener, so Xray does not create a separate exit or bypass KTest route policy.
- For ARM64, Balanced/Fast now launch **one pinned, official XTLS/Xray-core v26.10.10 Android executable** (`libxray.so`) from the APK's read-only `nativeLibraryDir`. Its release ZIP SHA-256, executable SHA-256 and 16 KiB ELF `PT_LOAD` alignment are verified during packaging; the executable's SHA is verified again at runtime. A private temporary JSON configuration exposes only an IPv4 loopback SOCKS5 port with Xray `freedom.fragment` (`tlshello`); the config is removed when the child process exits. The packaged executable never needs to download profile subscriptions, remote accounts or geo assets.
- In Balanced/Fast, the existing Go engine still chooses and races eligible routes per connection; the local Xray TLS-fragment strategy remains one optional TCP path. The Xray TUN process is a separate packet adapter only. If it fails startup or exits, Go starts HEV on the same TUN fd automatically and reports the selected adapter and fallback reason. Neither a running process nor a local SOCKS handshake proves a target is reachable.
- Only explicit offline method diagnostics remove ByeDPI `--auto` and `--auto-mode` flags to isolate a measured method. Connected Balanced and Fast retain the original adaptive strategies. No offline result pins live traffic.
- **Domain visibility:** Xray TUN enables HTTP/TLS/QUIC sniffing before forwarding flows to Go SOCKS. When automatic fallback selects HEV, HEV may supply only the numeric destination address, so Go still uses its existing HTTPS SNI recovery for IP-addressed TLS flows. Non-TLS MTProto is unchanged. An installed CA does not grant all apps user-CA trust, and the local Xray fragmentation profile does not itself use the CA.
- **Provenance:** `internal/xraycfg/android-cores.json` is the authoritative ARM64 release/binary checksum manifest; `android/scripts/prepare-native-cores.py` packages it under `lib/arm64-v8a` and ships the official MPL license. Windows CI executes upstream `xray.exe run -test` against the generated local fragmentation profile. Go tests statically verify that the TUN profile has only one loopback SOCKS outbound; starting that profile still requires a real Android TUN fd and physical-device validation.
- Whole-device Xray-first/HEV-fallback forwarding remains a **beta**. It still needs physical ARM64 phone tests for TCP/UDP/DNS/IPv6, actual foreign egress, fallback after process failure, leaks, roaming/reconnect, user-CA rejection and battery life. The Android installer's version is independent of the processor's ARMv8 ABI name.

## Android domain-fronting activation and reachability diagnostics

- The Settings screen now can check **the exact exported CA bytes** in the Android `AndroidCAStore` aliases beginning with `user:`. A matching fingerprint means **installed in the Android user CA store**, not that other apps trust it. Android 7+ apps typically do not trust manually installed user CAs unless configured to do so; apps with certificate pinning may always refuse. The user can explicitly opt in to **optional domain fronting** after that check, and disable it independently. Every opted-in Balanced/Fast connection checks that the exact certificate is still installed, then the Go proxy loads the matching private key and inserts the original Windows `front.Fronter` upstream. No automatic trust-store modification or global CA acceptance occurs.
- Fronting uses the existing, evidence-based provider families in `internal/front/rules.go`. Custom targets identify exact hosts; enabling their fronting option requires an existing supported family and coverage by the existing CA constraints. Adding a URL cannot invent a CDN strategy, broaden the CA, or enable arbitrary fronting. Android Balanced pins the tested method for each configured target; other destinations race and learn live; Fast retains front-family hedging and learned fallback while respecting the same opt-in and exit policy. An HTTPS response does not prove login, media delivery or native-app trust; if an app rejects the CA, disconnect and adjust/retest the configuration explicitly. See [route calibration](../docs/ANDROID_ROUTE_CALIBRATION.md).
- Opt-in quickcheck now separately tests **TikTok** (`https://www.tiktok.com/`), **Telegram website** (`https://telegram.org/`) and **Telegram Web** (`https://web.telegram.org/a/`), with short, TLS-validated HEAD requests and no cookies or redirects. A blocked HTTP response is categorized as *service response*, not falsely as a DPI signature. The Android diagnosis tool includes one-tap URLs for TikTok and Telegram Web. These checks are not proof the TikTok or Telegram native mobile apps work.
- **TikTok is intentionally not added to the fronting CDN-family table.** Its various video/API/CDN domains and edge anti-fronting controls require actual shared-edge routing proof per domain; guessing a front based on a blocked homepage risks routing to the wrong server. Balanced and Fast both connect without automatic method tests and adapt from live traffic. A region-rejected service needs a verified foreign route rather than an invented CDN front.
- **Telegram is also not in the fronting-family table.** The HTTPS marketing site `telegram.org` is not the Telegram Web SPA, and native Telegram uses MTProto and data-center IPs on top of TCP (and sometimes other transports). Domain fronting for an HTTPS Host cannot by itself carry raw Telegram MTProto or overcome an IP-level block. If the site check passes but the app fails, inspect the app's actual route, whether the Android VPN is enabled, IPv4/IPv6 and DNS, and MTProto proxy/tunnel reachability; never infer the censorship layer solely from a failed host.

## Optional local CA generator (manual Android trust)

Settings → **Local certificate generator** now reuses the **same Go `internal/front` CA generator as the Windows CLI**. The user taps **Generate local CA** to create an ECDSA P-256, two-year, name-constrained CA in `Context.filesDir/fronting-ca/`. The private key (`ktest-ca.key`) remains in app-private storage and is **never returned through the Go/Java bridge, saved by the Android document picker, included in an APK, or installed into the Android trust store**. Generation never silently overwrites an existing or partial CA.

**Save public certificate (.crt)** uses Android's `ACTION_CREATE_DOCUMENT` picker and exports only `ktest-ca.crt` in PEM form. To trust it manually, find **Android Settings → Security & privacy → More security settings → Encryption & credentials → Install a certificate → CA certificate** (menu names vary by vendor and Android version), select the exported file, and approve Android's security prompt. It may be necessary to choose a screen lock. The in-app status means only *created and locally validated*: it intentionally never claims Android system trust, domain-fronting availability or access to a site. Android 7+ apps generally do **not** automatically trust user-installed CAs, and TLS-pinning apps can refuse them even if they are installed.

Generating or installing the CA alone does not activate optional fronting, enable packet processing, or establish reachability. Activation requires the explicit trust/consent flow above and applies only within its supported routing/CA constraints. To reverse trust, remove the user-installed CA via Android system credential settings. Uninstalling KTest deletes the private key but **does not remove a manually installed Android trust anchor**; users should remove it separately. Do not export/share the key file or install CAs from untrusted sources.

## Native Aether packaging

The pinned v2.3.2 release includes dedicated Android arm64, ARMv7 and x86_64
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
again inside the final APK.

Aether Auto now gives one ordinary H2, H3 and WireGuard profile a native turbo
scan before revisiting the original full-scan profiles, within the existing
four-minute startup budget. Explicit methods and nested bootstrap retain their
configured policy. Automatic MASQUE attempts yield when the native core reports
that its completed scan found no usable gateway; an internal probe timeout alone
does not stop fallback. Saved-key preflight is bounded to eight seconds per
attempt and preserves inconclusive keys. Both key probes and carrier processes
use the shared managed runner, so inherited `RUST_LOG=warn` cannot hide the
acceptance markers. These are source-level scheduling guarantees; successful
ARM-device connectivity still requires runtime evidence. Preview packaging now
also triggers on shared `internal/**`, `go.mod` and `go.sum` changes.

Balanced/Fast also package the unmodified ByeDPI v0.17.3 static executable as
`libciadpi.so`, pinned by archive and executable hashes in
`internal/byedpi/android-cores.json`. The same preparation script checks its ELF
architecture/alignment and final APK bytes. The original strategy list and
parser live in `internal/byedpi` and are shared with the CLI. Go starts private
loopback SOCKS listeners, races these paths alongside direct routes, removes
exited children and reaps all owned processes on disconnect. No executable is
downloaded or copied to writable app storage at runtime. ByeDPI is a local
anti-DPI transport; it does not change the public exit IP.

Balanced/Fast now request a packaged foreign exit automatically when real
traffic exhausts or stalls the local routes, or immediately for protected
services. Concurrent requests share discovery; local listeners remain usable.
Balanced offers Aether, Psiphon/CDN and Tor, with independent startup slots;
standalone Psiphon/Tor retain direct transports and separate local anti-DPI
carrier variants without depending on WARP enrollment. Each backend profile
has its own stable private state directory, so concurrent attempts cannot
overwrite each other's helper configuration or datastore. Psiphon's native
DNS uses the existing encrypted Go wire-DNS path over a private loopback
listener, without forcing its direct QUIC traffic through a TCP-only proxy.
Fast includes local Xray but
excludes all Psiphon/Tor backends, allowing native Aether exits only. A successful
profile and hashed destination ranking hints are stored privately per network
and mode for 24 hours. A working core remains alive until disconnect or failure;
the Go session reaps losing attempts and recovers after a dead core. Windows
Zapret2 is not packaged or emulated on Android. Native H2 Aether attempts can
also use a private Go/ByeDPI carrier, sharing the running local cores and
avoiding recursive discovery or a foreign proxy for bootstrap. UDP transports
stay independent. These are implementation
capabilities; native app feeds, media playback and handovers require device
testing on the actual network.

The shipped ABI set remains ARMv7 and arm64; x86_64 is an optional native-check
target. The pinned arm64 executables meet at least 16 KiB ELF load alignment.
The x86_64 helper executables have 4 KiB alignment and are not a claim of 16 KiB
emulator/device support.

On `KTest_API_35` / `emulator-5558`, both Balanced and Fast now carry
certificate-verified HTTPS to the main YouTube, Discord and Wikipedia pages
through the actual VPN/TUN, with HTTP 200 responses and response-body bytes.
The in-app checks passed 4 of 5 targets after identifying the probe's User-Agent
(Wikipedia rejects the generic Go client). The Telegram website still failed
on the tested Android and Windows paths. Disconnect removed the TUN and all
app-owned ByeDPI children. These observations do not establish foreign egress,
video playback, Telegram app traffic or physical ARM-device acceptance.

Native help/version commands initially ran in the emulator shell. Later
validation builds launched Aether and its Psiphon helper under the app UID on
`emulator-5554`. UI Cancel removed the native parent and helper in about 0.14s;
a forced parent exit also removed the helper and surfaced an error without
publishing a connection. These are lifecycle observations on one emulator,
not proof of native Internet egress or a full-device VPN.

The service now calls `StartNativeProxy` with `ApplicationInfo.nativeLibraryDir` and app-private state. Aether owns initial enrollment, gateway scans and native reconnect; Android does not invoke a second Go enrollment/scanning supervisor. Startup, cancellation and native exit are tied to the shared process runner. The existing Go policy proxy remains to enforce verified-exit leases and protected routing. Aether/Psiphon native execution under the app UID has been observed on emulator-5554; verified foreign egress and sustained native traffic remain separate acceptance requirements.

## Release gate

**Final release remains gated.** A validation APK is not a release-ready app. `.github/workflows/android-build.yml` builds dedicated-signer preview artifacts on manual dispatch and scoped changes on `main`; required signing secrets are checked before expensive work. It does not publish a production release. Separate Go CI performs source/test checks. Route calibration, CSV export, same-signer updates, CA retention, JNI/TUN traffic, leaks, battery and reconnect behavior for this candidate still need physical-phone evidence; the main integration report must record the actual candidate and results.

Before calling this an Android port complete, validate the Xray TUN primary path and HEV automatic fallback on physical phones and real networks, including the actual SOCKS UDP/DoH path, dual-stack behavior, failover, leak prevention, roaming and battery use. Continue preserving Go's mode/egress policy and verify actual destination access instead of treating process startup as success. An Aether release supporting Termux is not automatically an app integration: Android 10+ restricts executing downloaded files from a writable app home. Native packaging must meet [Android's executable-code rules](https://developer.android.com/about/versions/10/behavior-changes-10#execute-permission), rather than adding a download-and-exec workaround.

### Implementation status, 2026-10-18

| Area | Implemented in source | Still required |
| --- | --- | --- |
| Shared Go connection | Shared SOCKS/HTTP lifecycle and managed native launch/cancel/exit handling | Full lifecycle/reconnect device evidence; no wholesale supervisor port |
| Fast | Adaptive Go/ByeDPI/Xray routes without preconnection calibration; automatic native Aether fallback, private network history, packet DNS and verified-exit UDP | Physical-device startup speed and recovery evidence |
| Balanced | Adaptive Go/ByeDPI/Xray local routes, shared DNS and verified-exit UDP policy; Xray TUN is the preferred whole-device packet adapter with automatic HEV fallback | Physical-device route, expiry/fail-closed, Xray-to-HEV failover and reconnect evidence |
| Aether | Packaged core launch, method selection and optional external SOCKS; native scans/reconnect reused | Verified native egress and sustained traffic |
| Tor / Psiphon | Existing Aether backends connected to Android, shared Tor verification and foreign-exit checks | Real egress and sustained traffic; process launch alone is insufficient |
| Windscribe / through Aether | Shared carrier probe exposed to Android | Operational native bridge, catalog/profile integration and authenticated data |
| UDP / DNS | Real SOCKS UDP, wire DoH, DNS over UDP/TCP, no direct UDP fallback; Xray TUN primary and HEV fallback | Public-exit data-plane tests, DNS leak tests and physical-device TUN validation |
| IPv6 / whole-device VPN | IPv6 packet encoding and platform wiring | Dual-stack public egress, leak tests and device approval gates |
| CDN / ECH tools | Shared provider inventory, finite/continuous scans, complete private CSV and bounded UI results, target front/ECH diagnostics | Android picker/measurement evidence and native-app outcomes remain separate |
| MITM / CA | Private local CA, explicit Android consent/trust flow, optional activation within existing family/CA constraints | Native-app trust, pinning and physical-device acceptance |
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
