# ktest for Android — diagnostic foundation

This first Android slice is **not a VPN**. It runs the real Go `internal/pathdiag` DNS/TCP/TLS diagnostic through a small `mobilebridge` AAR, shows stage-level results, and lets the user check for official Android APK updates. It never modifies network routes, trust stores, DNS, or Android VPN settings.

## Decisions

- Keep Go as the network core and Kotlin/Jetpack Compose as the UI.
- Do not spawn desktop `.exe` files on Android.
- Preserve optional domain-fronting / MITM and CA code **unchanged** in `internal/front`; do not ask for a CA in v0.1.
- For a future VPN mode, first validate HEV (MIT licensed, upstream AAR/JNI supported) to turn a `VpnService` TUN FD into an existing SOCKS5 proxy. Android has **no built-in tun2socks engine**.
- Current `internal/smartproxy` is TCP-oriented. Do not advertise all-app / UDP VPN until SOCKS5 UDP, DNS, IPv6, protect(fd) and reconnection are tested end-to-end.
- Xray and sing-box remain **optional candidates**, not concurrent bundled engines. Measure before choosing a larger stack.
- Do not add `VpnService` or risky installation permissions until the feature exists and is tested.

## Build

Prerequisites: Android SDK (API 36), NDK r28+, Java 17+, Go version from `go.mod`, `gomobile`, Gradle 9.5+.

From the repository root:

```sh
go install golang.org/x/mobile/cmd/gomobile@latest
go get -tool golang.org/x/mobile/cmd/gobind
gomobile init
mkdir -p android/app/libs
gomobile bind -target=android/arm64 -androidapi=26 -o android/app/libs/mobilebridge.aar ./mobilebridge
gradle -p android :app:assembleDebug
```

The Android build workflow on the feature branch does these steps on GitHub Actions. We intentionally do not commit generated AARs or unsigned APKs to source control. The app has no fake/placeholder diagnosis. The first build still needs to pass CI/device validation.

## UI / updates

The home screen runs bounded Go diagnostics for a user-selected URL, and labels DNS/TCP/TLS separately. Results are for the system default network only (they are **not** independent mobile-data/Wi-Fi measurements). Output stays on device.

The settings screen checks the official `Nishef1/ktest` GitHub releases endpoint on request. It offers an external browser link **only** if a newer Android APK asset exists. It does not silently download or install packages. Published APK updates require the same Android application ID and signing certificate as the installed APK; keep signing secrets outside GitHub.

For a Play-distributed variant, use Google Play In-App Updates instead of GitHub release checking. Connectivity issues can prevent update checks, so releases should also be independently distributable.

## Next gates

1. Verify arm64 AAR/APK CI output and on-device DNS/TCP/TLS status.
2. Verify TLS trust roots, captive portal behavior, IPv4/IPv6 differences, background transitions, and 16 KB native library alignment.
3. Extract Go SOCKS mode behind the mobile API only when it is truly usable on Android.
4. Benchmark HEV+SOCKS against a single integrated sing-box path with identical traffic and phone conditions; activate VPN only after UDP/DNS safety gates pass.
