# KTest Connection — Android preview v0.2.0

The app now has a **Connect / Disconnect dashboard**, not a diagnostic-first home page. Its display language is English only.

## What works

- The central animated power control starts/stops a **real**, foreground-managed, loopback-only Go SOCKS5 proxy and an HTTP proxy bridge (via existing `internal/smartproxy` and `internal/httpproxy`).
- The two built-in desktop **Balanced** and **Fast** plain/ClientHello-splitting paths are wired. No Xray, Aether, Windscribe, Psiphon or Tor executables are bundled on Android yet.
- Known protected AI hostnames have an `ExitOnly` restriction; without a verified foreign exit they fail closed **when identifiable by hostname/SNI**. IP-only requests that cannot be attributed to a domain are an explicit limitation; do not rely on this as an identity-protecting VPN.
- Live SOCKS5 and HTTP listeners use ephemeral `127.0.0.1` ports and are displayed in the UI for users to configure in compatible apps.
- Long-running listeners are owned by a foreground service with a persistent notification and Disconnect action. Starting/stopping is driven by a real Kotlin service calling the Go core.
- Tools tab provides bounded real DNS/TCP/TLS diagnostics. Settings keeps manual release update checks.
- Mode selector shows all the terminal's main modes: Balanced, Fast, Aether, Psiphon, Tor, Windscribe Local, Windscribe + Aether. **Unavailable** modes are labeled and cannot be connected; no fabricated status.
- No CA installation or global system network modification. MITM, CA and fronting code remain untouched in the existing Go source tree.

## What does not work yet

This **is not an Android VPN**. The power button means a local proxy is listening, **not** that device-wide traffic is tunneled or that a remote destination has been reached. Only apps explicitly configured to use `SOCKS5` or `HTTP` proxy will use it. Most ordinary Android apps don't expose an individual proxy setting, and the stock Wi-Fi HTTP proxy setting is not a system-wide SOCKS5 solution. This preview does not implement HEV/tun2socks, UDP, IPv6 end-to-end VPN, per-network socket binding, background autostart or verified foreign exit.

HEV remains the planned lean adapter when we integrate `VpnService`, after binding/protecting upstream sockets and validating DNS and UDP end to end. No Rust rewrite.

## Build

Use Android SDK 36, NDK r28c, Java 17+, Go from `go.mod`, `gomobile` and Gradle 9.5+.

```sh
go install golang.org/x/mobile/cmd/gomobile@latest
go get -tool golang.org/x/mobile/cmd/gobind
gomobile init
mkdir -p android/app/libs
gomobile bind -target=android/arm,android/arm64 -androidapi=26 -o android/app/libs/mobilebridge.aar ./mobilebridge
gradle -p android :app:assembleDebug
```

CI uses debug signing for preview only. Find `KTest-Connection-v0.2.0-preview.apk` inside the matching Actions ZIP artifact. Extract it first. Temporary CI signing keys aren't stable across runs; you may have to uninstall an earlier CI-signed preview before installing another (this clears local app data). Stable update-over-install requires a persistent **secure release signing key**; renaming files never fixes signature mismatches.

## Safety / remaining checks

1. Run Android APK CI, verify arm32/arm64 native libraries and signature.
2. On-device: test that Connect starts listeners, other apps can use the local SOCKS5/HTTP proxy, Disconnect closes all connections, notification stops service, and screen-off lifecycle works.
3. Verify that a non-Iran foreign exit is required for protected services, including unresolved/IP-only cases, before claiming privacy protection.
4. Test HEV + proxy against real mobile networks and implement controlled Android VPN permission, socket `protect()`, UDP, DNS and IPv6 routing and fail-closed recovery.
5. Evaluate Aether, Windscribe, Tor, Psiphon integration only with Android-compatible engines and meaningful transport verification.

The Android foreground service currently declares `specialUse` with an explicit subtype. Google Play publication will require confirming the permitted use case and developer declarations.

