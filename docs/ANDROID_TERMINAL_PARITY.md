# Android and terminal parity

Reviewed against KTest main at code commit `b489217` on 2026-10-22. This document describes shared mode behavior, the IPv6/ECH follow-up and the IPv6 provider scanner; it does not claim physical-device acceptance.

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
- Android Tools exposes explicit IPv4-only and IPv6-only provider CDN scans through the shared Go candidate-source policy. This tests HTTPS to a provider-owned hostname; it does not prove custom-domain fronting or create a Worker tunnel.
- The terminal input reader now clears its pending-request state before publishing an input line, preventing a lost back-to-back request; a regression test exercises 1,000 consecutive line requests.

## Validation status

The latest code commit `b489217` passed all three CI workflows:
- [Verify: Linux/Windows Go tests, race, formatting and Android source](https://github.com/Nishef1/ktest/actions/runs/39740660654).
- [Android APK build and signature verification](https://github.com/Nishef1/ktest/actions/runs/39740660796).
- [Windows portable package](https://github.com/Nishef1/ktest/actions/runs/39740660738).

Physical-device network acceptance remains outstanding.

## Physical-device acceptance still required

- On a physical Android device, test fast repeated taps, connect/cancel during startup, 20 connect/disconnect cycles, process background/termination, Wi-Fi-to-cellular handover, VPN permission revocation, DNS and IPv6 leak checks, UDP, sustained HTTPS traffic, and confirm saved MASQUE calibration is used on the next native connection.
- Confirm that Android's UI says “VPN active” only for a live packet adapter and never equates that with successful HTTPS to every destination.
- On Windows, verify the same mode details and route policy in TUI, explicit WireGuard startup without MASQUE calibration, and `aether-fragment=off` with H2 and WireGuard profiles.
- Do not treat a passing build or a listening local port as proof of live Internet access. Record the tested commit, OS/device, network, mode, coverage and exact result.

## Remaining platform-specific responsibilities

- The general provider CDN scanner UI currently exists on Android only; the terminal's CDN menu is Windscribe-focused. The candidate-source logic is shared, but a matching general CDN scan screen/command remains a parity gap.
- Android: foreground service lifecycle, VPN permission, TUN fd, underlying-network binding, notifications, app UID exclusion and OS process death.
- Windows: console capabilities, administrator elevation, Wintun/TUN, child-process jobs and external Windscribe integration.
- Both: Go route policy, profile filtering, DNS/DoH, verified exit handling, failure classification and mode semantics.
