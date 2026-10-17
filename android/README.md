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
gomobile bind -target=android/arm,android/arm64 -androidapi=26 -o android/app/libs/mobilebridge.aar ./mobilebridge
gradle -p android :app:assembleDebug
```

The Android build workflow on the feature branch produces a **debug-signed preview** named `KTest-Connection-Lab-v0.1.1-preview.apk` inside a GitHub Actions ZIP artifact. Extract the APK from the ZIP before installing. The preview is not a signed production release. No generated AAR or APK is committed to source control. The app has no fake/placeholder diagnosis. CI only checks build/signature/archive/ABIs; physical-device installation and runtime still require testing.

## UI / updates

The home screen runs bounded Go diagnostics for a user-selected URL, and labels DNS/TCP/TLS separately. Results are for the system default network only (they are **not** independent mobile-data/Wi-Fi measurements). Output stays on device.

The settings screen checks the official `Nishef1/ktest` GitHub releases endpoint on request. It offers an external browser link **only** if a newer Android APK asset exists. It does not silently download or install packages. Published APK updates require the same Android application ID and signing certificate as the installed APK; keep signing secrets outside GitHub.

For a Play-distributed variant, use Google Play In-App Updates instead of GitHub release checking. Connectivity issues can prevent update checks, so releases should also be independently distributable.

## Next gates

1. Verify ARMv7 + ARM64 AAR/APK CI output and on-device DNS/TCP/TLS status.
2. Verify TLS trust roots, captive portal behavior, IPv4/IPv6 differences, background transitions, and 16 KB native library alignment.
3. Extract Go SOCKS mode behind the mobile API only when it is truly usable on Android.
4. Benchmark HEV+SOCKS against a single integrated sing-box path with identical traffic and phone conditions; activate VPN only after UDP/DNS safety gates pass.

## Installation troubleshooting

- Download the **ZIP** workflow artifact and extract **KTest-Connection-Lab-v0.1.1-preview.apk**. Do not try to install the ZIP.
- Minimum supported Android version is **8.0** (API 26). This preview packages Go native libraries for `armeabi-v7a` and `arm64-v8a`; Intel/x86 Android devices are **not supported** by this APK.
- A new ephemeral debug signing key is created on each GitHub Actions runner. Therefore installing a new Actions preview **over an earlier CI preview with the same package ID can fail with a signature conflict**. For a test-only install, uninstall the earlier `com.nishef.ktest` first (this deletes its local app data), then install the new preview. Do not use this mechanism for production updates.
- Before public or in-app updates, set up an owner-controlled persistent signing key in encrypted GitHub Actions secrets, separate signed release workflow, and publish verified Android APK release assets. A filename change is **not** a signing fix.
- To collect an exact install failure reason, run `adb install -r KTest-Connection-Lab-v0.1.1-preview.apk` and check the `INSTALL_FAILED_*` code; do not diagnose from the filename alone.
