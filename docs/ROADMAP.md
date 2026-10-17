# Engineering roadmap (reviewed 2026-10-17)

Current target: finish Android integration of the existing KTest modes and tools by reusing upstream cores. The Android port is **incomplete**. Source compilation, packaged executables and a listening proxy are separate milestones from an authenticated connection or a working device-wide VPN.

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

The pinned Aether v2.3.0 release already builds Tor support with `--features tor`. Its [Psiphon build script](https://github.com/CluvexStudio/Aether/blob/v2.3.0/psiphon-build.sh) uses `CluvexStudio/psiphon-tunnel-core`, branch **`shirokhorshid`**, pinned to `83aa73b9b982e7421e00117f5b0c5aceb5dda452`. The prepared x86_64 helper's Go build metadata matches that revision with `vcs.modified=false`. A separate Psiphon download/build path is unnecessary for the selected bundle. This is provenance, not evidence that a fork is faster or that a live tunnel works. See [third-party notices](THIRD_PARTY_NOTICES.md) and the pinned upstream [release build](https://github.com/CluvexStudio/Aether/blob/v2.3.0/.github/workflows/release.yml), [runtime](https://github.com/CluvexStudio/Aether/blob/v2.3.0/aether/src/lib.rs) and [SOCKS implementation](https://github.com/CluvexStudio/Aether/blob/v2.3.0/aether/src/socks.rs).

## Current status

| Area | Checked implementation | Required to finish |
| --- | --- | --- |
| Shared lifecycle | CLI/mobile SOCKS/HTTP session lifecycle, scoped child-process cleanup | Thin Android native-core start/stop integration; do not port the whole CLI supervisor |
| Native bundle | Pinned Android Aether/Psiphon/Lyrebird payloads, archive/file verification and packaging script | Execution under the app UID, correct private state/helper paths, distribution notices |
| Balanced / Fast | Existing Go direct/splitting subset and shared routing policy | Wire existing native local strategies and validate mode behavior on a device |
| Aether | External loopback SOCKS works at the API level; shared method catalog and native argument construction | Launch the packaged Aether binary from the Android service and validate a real session |
| Tor / Psiphon | Aether already supplies these backends; desktop modes select them | Android lifecycle/configuration and mode-specific live verification; no new Tor/Psiphon engine |
| Windscribe / through Aether | Local-only / WARP-carrier policies and a shared carrier probe exist | Android bootstrap and supported Windscribe integration; authenticated end-to-end data |
| UDP / DNS / IPv6 | Shared Go UDP relay, wire DoH, TCP DNS and IPv6 address encoding have loopback coverage | Prefer native packet support when the selected backend supports it; prove public egress, DNS behavior and HEV/TUN forwarding per mode |
| Whole-device VPN | VpnService and HEV adapter source exists | Device packet-path, feedback-loop, leak and reconnect validation; readiness gates remain false |
| GUI / tools | Connection, Tools and Settings; bounded CDN scan and selected diagnostics | Connect method controls to native launch; complete required CLI tool/settings parity and interaction checks |
| MITM / CA | Existing optional Go implementation retained | Review equivalent Xray functionality before extending it; preserve explicit consent and domain/trust restrictions |
| Verification / release | Go CI, Android source compilation, pinned payload verification; limited emulator shell help/version checks | App-UID/JNI/device/network/battery/signing evidence; APK/AAR production remains on hold |

An `Aether to Tor` / `Aether to Psiphon` label selects an Aether backend; it does not authorize adding a WARP hop to the current Tor-only/Psiphon-only policies. Aether does not replace Windscribe, Xray or ByeDPI merely by having Tor/Psiphon support. See [mode contracts](CONNECTION_MODES.md).

## Implementation order and acceptance gates

1. **Thin native integration.** Connect the verified native bundle to Android's service using the shared process runner, supported method flags, explicit helper paths and private state. Let Aether perform its own scans and native reconnects. Cancellation must terminate owned descendants. Native exit must clear connection eligibility. Port required behavior, not all CLI machinery.
2. **Validate the simplest packet path.** For a compatible single-core mode, evaluate HEV directly against that core's SOCKS endpoint before extending the Go relay. A direct path is acceptable only with equivalent mode enforcement, verification expiry and fail-closed behavior. Aether SOCKS UDP support does not establish UDP support in every Tor/Psiphon backend. Mixed modes may still require KTest routing. Validate DNS/UDP/IPv6, feedback prevention, disconnect and network changes before enabling VPN readiness gates.
3. **Remove superseded management.** For each proposed deletion, identify live callers and the upstream replacement, then verify the same behavior through that replacement. Review CLI profile racing, periodic health retirement, staged enrollment and the Go proxy in pure-core modes. Keep explicit comparison tools separate from native gateway scanning. Do not kill a reconnecting core solely because a diagnostic destination is blocked.
4. **Finish the interface and mode adapters.** Expose existing core options and existing Go diagnostic functions. Complete the supported Windscribe path separately. Verify progress, cancellation, errors, settings and reconnect through real interaction; avoid new networking engines in Kotlin.
5. **Validate and release only when authorized.** Run source checks first, then app/native/JNI/HEV tests on physical phones and relevant networks, leak and battery tests, licensing/notices and stable signing. The standing hold on producing a fresh APK/AAR remains in effect; do not dispatch the manual release workflow as part of source work.

## Code reuse audit (2026-10-17)

| Code / responsibility | Decision | Evidence / remaining condition |
| --- | --- | --- |
| Unused `warpManager.waitWhileConnected` / `waitRetry` | Removed | No callers; the active manager loop already handles those states |
| `aetherLauncher` and manager DNS-result plumbing | Removed | Launcher ignored the DNS result; both native launch sites now call the shared `aether.Run` directly |
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
