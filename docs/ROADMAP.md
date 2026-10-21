# Engineering roadmap (reviewed 2026-10-21)

Current target: finish Android integration of the existing KTest modes and tools by reusing upstream cores. The Android port is **incomplete**. Source compilation, packaged executables and a listening proxy are separate milestones from an authenticated connection or a working device-wide VPN.

**Current source snapshot:** [2026-10-21 audit](CURRENT_AUDIT_2026-10-21.md). The latest checked commit passes its Go/race/formatting, Android source, Android APK and Windows portable CI jobs; physical-device, current ISP and resource-efficiency acceptance remain open.

This roadmap supersedes the October 13 research-only phase table. Historical experiments remain documented in [RESEARCH.md](RESEARCH.md), [EXPERIMENTS.md](EXPERIMENTS.md), [ACCESS.md](ACCESS.md), [REVIVE.md](REVIVE.md) and [FRONTING.md](FRONTING.md); they do not describe current Android readiness.

## Architecture decision: use the existing cores

Before adding networking code, ask: **does the selected upstream core already provide this capability?** If yes, configure and use it. Add Go/Kotlin code only for a demonstrated integration or KTest policy gap. Record that gap and its consumers before introducing another implementation.

| Responsibility | Owner | KTest integration boundary |
| --- | --- | --- |
| MASQUE H2/H3, WireGuard, Gool and nested MASQUE | Aether | Select a supported method and private paths; run the unchanged binary |
| Gateway discovery, native tunnel validation and reconnect within a method | Aether | Observe lifecycle; do not add another endpoint scanner or reconnect loop for that tunnel |
| Tor circuits and bridge/transport discovery | Aether's built-in Arti integration and bundled Lyrebird | Select Aether's Tor backend; verify Tor egress; no independent Go Tor manager |
| Psiphon transport and CDN mode | Aether and its bundled Psiphon helper | Use Aether's Psiphon options and explicit helper path; no independent Go Psiphon engine |
| Local Xray and ByeDPI techniques | Existing Xray / ByeDPI cores | Adapt their configuration and lifecycle where Aether does not provide the required local-only behavior |
| Windscribe VPN authentication and final tunnel | Windscribe | Integrate the required bootstrap/carrier; do not implement its VPN protocol or substitute a Psiphon exit |
| Android TUN packet conversion | HEV / tun2socks | Supply the fd and selected SOCKS endpoint; no second TCP/IP or VPN stack in Go/Kotlin |
| Mode policy, verified-exit eligibility and protected-route pinning | KTest | Keep only policy not supplied equivalently by the chosen core |
| App lifecycle, permissions and UI | Android plus a narrow Go bridge | Start/stop/cancel, private state, process cleanup, progress and errors |

The pinned Aether v2.3.2 release continues to build Tor support with `--features tor`. Its [Psiphon build script](https://github.com/patterniha/Aether/blob/v2.3.2/psiphon-build.sh) uses `CluvexStudio/psiphon-tunnel-core`, branch **`shirokhorshid`**, pinned to `83aa73b9b982e7421e00117f5b0c5aceb5dda452`. The prepared x86_64 helper's Go build metadata matches that revision with `vcs.modified=false`. A separate Psiphon download/build path is unnecessary for the selected bundle. This is provenance, not evidence that a fork is faster or that a live tunnel works. See [third-party notices](THIRD_PARTY_NOTICES.md) and the pinned upstream [release build](https://github.com/patterniha/Aether/blob/v2.3.2/.github/workflows/release.yml), [runtime](https://github.com/patterniha/Aether/blob/v2.3.2/aether/src/lib.rs) and [SOCKS implementation](https://github.com/patterniha/Aether/blob/v2.3.2/aether/src/socks.rs).

## Current status

| Area | Checked implementation | Required to finish |
| --- | --- | --- |
| Shared lifecycle | Shared SOCKS/HTTP lifecycle plus managed Android native-core launch/cancel/exit handling | Complete device lifecycle/reconnect evidence; no wholesale CLI supervisor port |
| Native bundle | Pinned payloads, runtime verification and observed Aether/Psiphon execution under the app UID on emulator-5554 | Validate each backend and ARM devices; distribution notices |
| Balanced / Fast | Go SmartProxy adaptive routing; nine packaged ByeDPI candidates plus official Xray TLS-fragment path and optional consented fronting on Android. No AI/TikTok-specific routing rule; exits are requested on demand after local failure/stall. | Physical-device startup/recovery and actual ISP/service acceptance; CPU/RAM/battery benchmarks |
| Aether | Pinned Aether v2.3.2 runtime, method selection, native scan/reconnect, WARP carrier policy for all managed traffic and bounded TLS-shape/F&F calibration. A working carrier may geolocate to Iran. | Verified end-to-end data plane, cold-start/reconnect stability and method-specific timing; Aether is not a foreign-IP guarantee |
| Tor / Psiphon | Existing Aether backends selected on Android; Psiphon/Tor require a verified non-Iran/non-Russia exit and fail closed without one. | Physical-device egress and sustained traffic; process startup is not a successful connection |
| Windscribe / through Aether | Desktop local-only bridge and explicit WARP-carrier mode are separate policies; Windscribe owns the final VPN IP. These modes are not exposed by the Android app. | Authenticated end-to-end Windscribe data; a ready carrier or HTTP CONNECT 200 is not VPN success |
| UDP / DNS / IPv6 | Shared Go UDP ASSOCIATE and wire-DoH policy; AliDNS RFC 8484 DoH is added as a pinned-IP HTTPS/SVCB fallback for ECH config lookup; Aether can carry managed UDP through WARP even if its IP geolocates to Iran. | Physical-device public egress, HTTPS RR/ECHConfig resolution, DNS/IPv6/UDP leak checks and per-mode acceptance |
| Whole-device VPN | Android Xray TUN primary with HEV fallback, using the same Go SOCKS policy; Windows whole-PC TUN remains separate and not a persistent OS kill switch. | Physical-device TUN lifecycle, leaks, roaming, battery and failure-recovery validation |
| GUI / tools | Redesigned UI: phase steps, uptime, per-target route checks, multi-edge fronting with origin proof, CDN-scan hand-off, packaged-core verification, open-source notices, launcher/notification icons; rendered on emulator | Physical-device/TalkBack checks and remaining CLI tool parity (Windscribe node catalog, Aether comparison) |
| MITM / CA | Shared Go fronting now requires explicit Android user-CA match and opt-in; IP-only HEV TLS flows recover SNI for routing | Test application-specific CA trust, encrypted ClientHello and site acceptance on physical phones; no automatic CA trust for third-party apps |
| Verification / release | Commit `978e0ab` passed Ubuntu/Windows tests, formatting, race, Android source checks, Android APK build and Windows portable packaging. | Re-run CI after this documentation commit; CI is not evidence of live ISP reachability, full app access or performance efficiency |

An `Aether to Tor` / `Aether to Psiphon` label selects an Aether backend; it does not authorize adding a WARP hop to the current Tor-only/Psiphon-only policies. Aether does not replace Windscribe, Xray or ByeDPI merely by having Tor/Psiphon support. See [mode contracts](CONNECTION_MODES.md).

## Current audit priorities (2026-10-21)

1. **P1 — avoid irrelevant calibration:** filter the selected Aether method before MASQUE/F&F calibration; a forced WireGuard method currently can still enter the MASQUE calibration path.
2. **P1 — make `fragment=off` truthful:** `tlsshape.Apply` removes the built-in `--fragment` flag, but later `WithExitNodes` can still add `tlshello-0-len` variants. Either suppress those variants too or label the setting precisely.
3. **P2 — measure, do not guess:** benchmark cold/warm connect latency (P50/P95), memory, CPU and battery on physical Android devices; the nine ByeDPI candidates plus optional Xray have not been profiled here.
4. **P2 — separate readiness from reachability:** report proxy/TUN readiness separately from a successful end-to-end HTTPS check; `tun_running_unverified` is not proof of Internet access.
5. **P2 — complete real-device acceptance:** test reconnects, network handover, DNS, UDP/IPv6, ECH and leak behavior with current APKs. Keep older emulator/ISP observations labelled by date.

See [current audit](CURRENT_AUDIT_2026-10-21.md) for the evidence matrix and exact source locations.

## Implementation order and acceptance gates

1. **Correct the measured-method path.** Skip MASQUE TLS-shape calibration when the selected method cannot use it; ensure cancellation, cache expiry and the 15-second budget are tested.
2. **Make settings match runtime behavior.** Define whether `fragment=off` disables only Aether's built-in fragmentation or every F&F/final-mask variant, then align profile generation, CLI/UI labels and regression tests.
3. **Separate readiness from verified access.** Expose listener-ready, packet-adapter-running, WARP-carrier-ready, verified foreign exit and destination HTTPS as distinct states. Do not equate `tun_running_unverified`, a SOCKS listener or HTTP CONNECT 200 with usable Internet.
4. **Measure performance on devices.** Run cold/warm latency P50/P95, RAM/CPU/thermal and battery benchmarks on physical Android hardware; compare the previous release and candidate under the same network. Include 20 reconnect cycles, Wi-Fi/cellular handover, DNS/UDP/IPv6 and TUN failover.
5. **Complete release acceptance.** Validate each supported Aether/Psiphon/Tor method separately, verify actual application data and leak boundaries, run current CI, review third-party notices and signing, and keep release blocked until the evidence is recorded. A debug APK or green CI is not a release certificate.
## Code reuse audit (updated 2026-10-18)

| Code / responsibility | Decision | Evidence / remaining condition |
| --- | --- | --- |
| Unused `warpManager.waitWhileConnected` / `waitRetry` | Removed | No callers; the active manager loop already handles those states |
| `aetherLauncher` and manager DNS-result plumbing | Removed | Launcher ignored the DNS result; both native launch sites now call the shared `aether.Run` directly |
| Legacy CLI HTTP bridge, process-kill/log helpers and unused probe measurement setter | Removed | No callers remained; the shared connection session owns the HTTP bridge |
| Test-only SOCKS peer / route-memory helpers | Moved out of production | Existing regression tests keep these helpers; runtime builds do not need them |
| `internal/coreprocess` | Retain | OS process groups / Job Objects own child cleanup; upstream tunnel reconnect does not replace app-owned process lifetime |
| `internal/aether` profile, identity and bundle contracts | Retain, keep narrow | Consumed by CLI/mobile; no MASQUE/WireGuard/Tor/Psiphon protocol implementation was added here |
| Staged identity enrollment | Retain pending equivalent native lifecycle proof | Native core performs registration; KTest staging currently protects saved identities from replacement and suppresses credential output |
| Go SOCKS/UDP/DNS and adaptive routing | Retain for existing consumers; do not make it mandatory for every future native mode | Current mixed-mode and mobile consumers depend on it; native-mode simplification requires equivalent policy and traffic evidence first |
| CLI cross-profile selection and health retirement | Review before reuse on Android | Choosing between independent methods is distinct from native endpoint scanning; copying the entire supervisor is no longer a prerequisite |
| Go MITM/fronting versus Xray | Replacement candidate, not removed yet | Compare actual configuration support and preserve explicit CA consent, certificate checks and scoped routing before deleting a working path |

## Evidence and safety boundaries

- DoH, DoT, ECH and individual diagnostic endpoints can be filtered independently. Failure is an observation about that path, not proof that all Internet access is unavailable. No silent plaintext DNS escape from a strict mode.
- Normal `windscribe` stays local-only. Only explicit `windscribe-aether` uses a WARP carrier; neither may silently become a Psiphon/Tor route.
- Preserve certificate verification for application/diagnostic HTTPS. Pinned Aether v2.3.0 has upstream TLS/API/reconnect limitations; reusing its core does not erase them. See [network diagnosis](NETWORK_DIAGNOSIS.md).
- Never silently install a CA or enable global proxy, routes, DNS or TUN. Keep credentials, identities, personal IP logs and raw field measurements out of this public repository. Bound scans and use permitted targets.
- Passing CI, `--help`, a SOCKS listener or HTTP CONNECT 200 is not proof of a working VPN. Report tested, failed, untested and not validated separately.

## Build findings (2026-10-18)

The first actual APK build exposed a missed dependency contract: pinned HEV 2.19.0 declares minSdk 29 while the app declared 26. The app now requires **Android 10+**, without overriding the upstream manifest. Source CI now uses the real pinned HEV AAR and merges its manifest, rather than substituting Java declarations alone. Go mobile tooling is pinned to the same version as source CI. Gradle owns native extraction through `useLegacyPackaging`; the merged APK manifest and native hashes must be checked.

Device checks observed native Aether/Psiphon parent/helper ownership, user cancellation (about 0.14s), cleanup after a forced native parent exit, mode changes after errors and actual certificate-verified HTTPS through the Android HTTP proxy (Balanced, example.com HTTP 200). Native Tor did not obtain a verified exit within its seven-minute budget; that result is not proof of universal blocking. UI checks covered the mode/method controls, errors, navigation, font scale 1.3 and long text input. The full verification boundary is recorded in [Android device observations](../android/README.md#device-observations-2026-10-18). Final app delivery remains open, including native egress, packet VPN, Windscribe, remaining tools and physical-device evidence.
