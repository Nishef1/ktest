# Android and terminal parity

Reviewed against KTest main on 2026-10-21 after PR #11 merged. This document describes the shared contract and the IPv6/ECH follow-up; it does not claim physical-device acceptance.

## What is already shared

- `internal/connectionpolicy` owns mode identifiers, canonical titles, Android availability, limitations and routing-policy configuration.
- Android reads the Go mode catalog through `mobilebridge.ConnectionModes()`; it must not invent transport modes.
- The terminal and Android call the same Go packages for Aether profiles, connection policy, DNS, route selection and connection verification. Kotlin owns Android lifecycle/VpnService integration, while the terminal owns console input/rendering and Windows elevation/TUN integration.
- Different UI layouts are intentional. The mode semantics, descriptions, status meaning and core routing behavior should not drift.

## Changes in this follow-up

- Mode details are now part of the canonical Go connection catalog. The terminal's `ConnectionMode.message()` delegates to the catalog, and Android displays the same detail instead of maintaining separate Balanced/Fast explanations.
- MASQUE calibration is skipped when the user explicitly selects a non-MASQUE transport such as WireGuard or WireGuard-in-WireGuard. Calibration measures MASQUE HTTP handshakes and should not add a startup delay to a transport that cannot use those results.
- `aether-fragment=off` disables Aether's own fragment flag and excludes TCP TLS-hello exit-node masks in both the CLI and Android automatic-exit profile generation. The independent UDP-noise exit-node remains available because it is a distinct UDP strategy, not TLS fragmentation. The Android label explains that separate local anti-DPI carrier strategies can still shape the outer connection.
- Android no longer claims that “all apps are connected” just because its local proxy and TUN adapter are active. It distinguishes system VPN readiness from per-destination reachability.
- Android native profile selection filters the requested mode and transport before applying MASQUE-only TLS shaping, so unrelated profile variants are not processed for an explicit method.
- The native Android path passes the app's private directory into profile construction and consumes saved TLS calibration for both explicit and Auto profiles. The per-network cache key is set before all connection modes and before the manual calibration action; previously the native path passed an empty directory and discarded the calibration result.
- The shared Aether profile list now includes non-ECH IPv6 variants for MASQUE H2 and WireGuard. IPv4 and IPv6 are separate quick-pass candidates, so an unavailable IPv4 path does not need to finish a full scan before IPv6 is attempted.
- Explicit Android method selection scans every profile in that transport family (including IPv4/IPv6 and ECH/non-ECH variants), while never switching from a selected method to a different protocol. This matches the terminal's filtered profile inventory.
- ECH bootstrap results are shared and caller waits are bounded. Registration now tries a working local proxy, the F&F exit-node/fragmentation routes, then ECH and Psiphon fallback rather than assuming the visible ECH SNI is always reachable.

## Validation status

The pre-follow-up parity code passed automated CI before PR #11 was merged. The IPv6/ECH follow-up commit is subject to a fresh CI run:
- Go unit tests on Linux and Windows.
- Go race tests and gofmt.
- Android source compilation and Android debug APK smoke build.
- Windows portable package build.

The successful checks are available at [verify](https://github.com/Nishef1/ktest/actions/runs/39680852294), [Android APK smoke](https://github.com/Nishef1/ktest/actions/runs/39680852335), and [Windows portable](https://github.com/Nishef1/ktest/actions/runs/39680852214).

## Physical-device acceptance still required

- On a physical Android device, test fast repeated taps, connect/cancel during startup, 20 connect/disconnect cycles, process background/termination, Wi-Fi-to-cellular handover, VPN permission revocation, DNS and IPv6 leak checks, UDP, sustained HTTPS traffic, and confirm saved MASQUE calibration is used on the next native connection.
- Confirm that Android's UI says “VPN active” only for a live packet adapter and never equates that with successful HTTPS to every destination.
- On Windows, verify the same mode details and route policy in TUI, explicit WireGuard startup without MASQUE calibration, and `aether-fragment=off` with H2 and WireGuard profiles.
- Do not treat a passing build or a listening local port as proof of live Internet access. Record the tested commit, OS/device, network, mode, coverage and exact result.

## Remaining platform-specific responsibilities

- Android: foreground service lifecycle, VPN permission, TUN fd, underlying-network binding, notifications, app UID exclusion and OS process death.
- Windows: console capabilities, administrator elevation, Wintun/TUN, child-process jobs and external Windscribe integration.
- Both: Go route policy, profile filtering, DNS/DoH, verified exit handling, failure classification and mode semantics.
