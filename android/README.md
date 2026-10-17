# KTest on Android — Go core with native UI

This directory contains **only the Android presentation and lifecycle adapter** for the existing KTest Go networking core. It must not grow a second implementation of Tor, Aether, Psiphon, Windscribe or the routing policies.

## Design rule

- **Core (Go):** existing `internal/smartproxy`, `internal/front`, `internal/probe`, routing and policy packages; these remain the source of truth.
- **Binding (`mobilebridge`):** narrow `gomobile bind` entrypoints to the actual Go core, with status and error reporting.
- **Android (Kotlin/Compose):** English-only selection, animated Connect/Disconnect, lifecycle/foreground notification, diagnostics and manual update checks. No independent network strategy or engine.
- Platform-specific TUN/VPN support is valid **only as an OS adapter** when the original Go core can drive it. Do not present a new HEV/Aether/Tor path as equivalent to the desktop CLI without implementing the same transport.

## Cleanup of parallel experiments

Removed the independent `KTestVpnService`/HEV VPN prototype, embedded Guardian Tor service and controller, their Android dependencies and download script, and mobile-only foreign-exit/UDP preflight implementations that supported those experimental paths. They were not part of the real desktop `connectSession` flow. No underlying Go MITM/CA, ECH, CDN/fronting or desktop engine source has been removed.

## What the UI currently exposes

The mode catalog and policy decisions come from the shared Go `internal/connectionpolicy` package, which is also called by the desktop CLI. All seven CLI modes remain **visible**, but unavailable paths are disabled:

| CLI mode | Android status |
| --- | --- |
| Balanced | Built-in Go adaptive TCP proxy subset; **not full desktop parity** (external desktop strategy launchers are not ported) |
| Fast | Same existing Go paths and Fast policy; **not full desktop parity** |
| Aether | Optional CLI-style **external loopback SOCKS5** entry only; managed Aether engine not ported |
| Aether to Tor | Disabled until the original managed Tor route can be driven by Go on Android |
| Windscribe | Disabled until the original local anti-DPI WStunnel/Xray/ByeDPI path is portable |
| Aether to Psiphon | Disabled because the CLI explicitly requires managed Aether Psiphon profiles; an arbitrary external SOCKS would violate its policy |
| Windscribe through Aether | Disabled until original Aether carrier and Windscribe bridge are portable |

Go-backed tools preserved: DNS/TCP/TLS diagnosis, controlled CDN/fronting probe, ECH bootstrap and proxy HTTPS route check.

## Development gate

**Do not produce an APK automatically.** `.github/workflows/android-build.yml` remains `workflow_dispatch` only. The ordinary test workflow validates Go source, formatting, vet and race without publishing feature-branch binaries. These tests cannot prove Android JNI compatibility, UI rendering, actual cellular networking or full CLI feature parity.

Next work is not creating more cores. It is extracting the remaining OS-independent desktop connection orchestration out of `cmd/ktest` into shareable Go packages, and invoking those same entrypoints from `mobilebridge`. Add Android-only adapters only where the existing Go engine explicitly requires OS capabilities. Manual device validation comes before release.
