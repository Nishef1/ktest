# Engineering roadmap (reviewed 2026-10-21)

## Upstream refresh (2026-11-23)

- **Included:** pinned PattNG Xray-core v26.11.23 for Windows and Android; pinned
  HEV 2.20.0 AAR matching PattNG P74 submodule; Serverless-for-Iran v65 A/B/OOB
  on Windows and Android as separately selected, localhost-only direct-IP modes.
- **Routing:** shared Go SmartProxy now periodically challenges an eligible
  alternative on application traffic; no idle phone network sweep. Windows
  retry of TUN startup/loss is bounded and keeps proxy-only fallback.
- **Explicit Android selection:** Fragment A/B/OOB now run only in standalone
  Android Serverless mode with SHA-verified original Xray and GeoIP/GeoSite
  assets. Its routing/DNS config and direct-to-ISP egress are never injected
  into Balanced/Fast or strict VPN exit modes; this remains proxy-only. Real
  phone/ISP acceptance and privacy/leak checks are still required.
- **Release acceptance remains open:** fresh Windows install first-connect,
  Android ARM64 physical-device TLS/UDP/DNS/IPv6/TUN-failover, leak testing,
  Wi-Fi/cellular handover, session latency/throughput and battery benchmarks.
  Green CI establishes compilation and test behavior, not access on the ISP.


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

The previously pinned Aether v2.3.2 release continues to build Tor support with `--features tor`. Its [Psiphon build script](https://github.com/patterniha/Aether/blob/v2.3.2/psiphon-build.sh) uses `CluvexStudio/psiphon-tunnel-core`, branch **`shirokhorshid`**, pinned to `83aa73b9b982e7421e00117f5b0c5aceb5dda452`. The prepared x86_64 helper's Go build metadata matches that revision with `vcs.modified=false`. A separate Psiphon download/build path is unnecessary for the selected bundle. This is provenance, not evidence that a fork is faster or that a live tunnel works. See [third-party notices](THIRD_PARTY_NOTICES.md) and the pinned upstream [release build](https://github.com/patterniha/Aether/blob/v2.3.2/.github/workflows/release.yml), [runtime](https://github.com/patterniha/Aether/blob/v2.3.2/aether/src/lib.rs) and [SOCKS implementation](https://github.com/patterniha/Aether/blob/v2.3.2/aether/src/socks.rs).

## Current status

| Area | Checked implementation | Required to finish |
| --- | --- | --- |
| Shared lifecycle | Shared SOCKS/HTTP lifecycle plus managed Android native-core launch/cancel/exit handling | Complete device lifecycle/reconnect evidence; no wholesale CLI supervisor port |
| Native bundle | Pinned payloads, runtime verification and observed Aether/Psiphon execution under the app UID on emulator-5554 | Validate each backend and ARM devices; distribution notices |
| Balanced / Fast | Go SmartProxy adaptive routing; nine packaged ByeDPI candidates plus official Xray TLS-fragment path and optional consented fronting on Android. No AI/TikTok-specific routing rule; exits are requested on demand after local failure/stall. | Physical-device startup/recovery and actual ISP/service acceptance; CPU/RAM/battery benchmarks |
| Aether | Reviewed Aether v2.4.0 upgrade (see `AETHER_240_AUDIT_2026-10-24.md`), method selection, native scan/reconnect, WARP carrier policy for all managed traffic and bounded TLS-shape/F&F calibration. A working carrier may geolocate to Iran. | Verified end-to-end data plane, cold-start/reconnect stability and method-specific timing; Aether is not a foreign-IP guarantee |
| Tor / Psiphon | Existing Aether backends selected on Android; Psiphon/Tor require a verified non-Iran/non-Russia exit and fail closed without one. | Physical-device egress and sustained traffic; process startup is not a successful connection |
| Windscribe / through Aether | Desktop local-only bridge and explicit WARP-carrier mode are separate policies; Windscribe owns the final VPN IP. These modes are not exposed by the Android app. | Authenticated end-to-end Windscribe data; a ready carrier or HTTP CONNECT 200 is not VPN success |
| UDP / DNS / IPv6 | Shared Go UDP ASSOCIATE and wire-DoH policy; AliDNS RFC 8484 DoH is added as a pinned-IP HTTPS/SVCB fallback for ECH config lookup; Aether can carry managed UDP through WARP even if its IP geolocates to Iran. | Physical-device public egress, HTTPS RR/ECHConfig resolution, DNS/IPv6/UDP leak checks and per-mode acceptance |
| Whole-device VPN | Android Xray TUN primary with HEV fallback, using the same Go SOCKS policy; Windows whole-PC TUN remains separate and not a persistent OS kill switch. | Physical-device TUN lifecycle, leaks, roaming, battery and failure-recovery validation |
| GUI / tools | Redesigned UI: phase steps, uptime, per-target route checks, multi-edge fronting with origin proof, CDN-scan hand-off, packaged-core verification, open-source notices, launcher/notification icons; rendered on emulator | Physical-device/TalkBack checks and remaining CLI tool parity (Windscribe node catalog, Aether comparison) |
| MITM / CA | Shared Go fronting now requires explicit Android user-CA match and opt-in; IP-only HEV TLS flows recover SNI for routing | Test application-specific CA trust, encrypted ClientHello and site acceptance on physical phones; no automatic CA trust for third-party apps |
| Verification / release | Commit `978e0ab` passed Ubuntu/Windows tests, formatting, race, Android source checks, Android APK build and Windows portable packaging. | Re-run CI after this documentation commit; CI is not evidence of live ISP reachability, full app access or performance efficiency |

An `Aether to Tor` / `Aether to Psiphon` label selects an Aether backend; it does not authorize adding a WARP hop to the current Tor-only/Psiphon-only policies. Aether does not replace Windscribe, Xray or ByeDPI merely by having Tor/Psiphon support. See [mode contracts](CONNECTION_MODES.md).

## Re-checked 2026-11-07

- **Resolved in source:** the two P1 items below. `sessionNeedsTLSCalibration` skips MASQUE calibration for Psiphon/Tor/Windscribe and forced non-MASQUE Aether methods; `fragment=off` drops the TCP `tlshello-0-len` exit-node variants and keeps only the UDP-noise fallback (`TestAetherFragmentOffSkipsTCPExitNodeMasksButKeepsUDPNoise`, `TestExitNodeFragmentOffDisablesOnlyTCPHelloMasks`). The list is kept for history.
- **Windscribe through Aether, desktop:** on 2026-11-07 the Windscribe app was Connected (OpenVPN TCP/443, Ashburn) with its HTTP proxy on ktest, and `windscribe-test -verify-vpn` matched the system HTTPS exit IP to the CLI's VPN IP. This confirms the sampled request only; other apps, DNS and the specific carrier were not tested. Windscribe CLI status parsing now accepts the newer `Login:` / `Connection:` / `IP: ... (VPN)` layout and no longer depends on the account's login line.
- **Still open (needs hardware or a live network):** every physical-device item, performance benchmarks, per-method Aether/Tor/Psiphon acceptance, TalkBack checks and release signing/notices.

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

### IPv4/IPv6 user-visible verification (2026-11-23)

Android previously verified only one public IP, with IPv4-pinned trace endpoints; the IP panel could not distinguish IPv4 and IPv6 observations. It now offers **IPv4 only / Both / IPv6 only** for independent HTTPS public-IP diagnostics. The Go bridge validates the requested family of the actual public IP; an IPv6 failure never silently reports an IPv4 success as IPv6. Successful dual-family data is retained separately for the UI. The Android TUN used to gate IPv6 on the **physical underlay** rather than the actual selected proxy; it now requires a pre-VPN certificate-verified IPv6 HTTPS trace through the active proxy before installing its IPv6 route. This permits IPv6 exits carried over IPv4 underlays and avoids advertising a v6 route merely because the physical Wi-Fi has IPv6.

### Destination-family enforcement and release gate (2026-11-23)

The separate **Destination IP family** connection setting now persists Both, IPv4 only or IPv6 only. Windows: menu 8 → 3, or `ktest connect -ip-family ipv6 -save`. Android: Connect → Destination IP family. The IP diagnostics selector is independent.

- Managed TCP, SOCKS and non-DNS UDP destinations in single-family mode must resolve to a numeric address of the selected family; an incompatible literal or an empty matching DNS answer fails closed. DNS queries for the excluded record type return NODATA; encrypted DNS infrastructure and native tunnel gateways are not application destinations.
- Windows production TUN adds an IPv6 fake-IP pool, explicit family rejection and family-aware DNS; Android configures only the selected family in single-family mode without allowing the excluded family. Both mode on Android can reconnect when an IPv6 route becomes independently verified.
- Single-family Serverless wraps the pinned Xray profile with the enforcing proxy and preserves numeric destinations instead of redirecting to other addresses. TLS fronting and incompatible manual route calibration are not used in strict mode.
- A verified foreign exit must prove the selected public IP family before authorizing strict traffic. Destination policy is not a forced physical carrier-family policy. Remote exits may translate or lack a family; a working path is not guaranteed. Windows LAN/helper exclusions, Android app-UID exclusions and proxy-only coverage remain; no persistent system kill switch is claimed.
- Windscribe owns its system VPN and final exit. KTest rejects its single-family connection setting rather than claiming control over another client's routing.

**Final release remains blocked** on the following evidence. Record the exact commit, device/OS, network type, sanitized result and observed failure for each case; never store credentials or personal IP logs.

- [ ] Latest commit: Go tests, race, vet, formatting, Android source, signed preview APK, Windows portable ZIP and native generated-config validation pass.
- [ ] Windows 11 and Android physical device: verify IPv4-only, IPv6-only and Both using independent HTTPS traces and actual applications; test literal IPs, A/AAAA, TCP, UDP/QUIC, HTTPS/SVCB and private/ULA behavior.
- [ ] Test IPv4-only underlay with IPv6-capable exit, dual-stack underlay with no working IPv6 proxy, IPv6-only/NAT64 where available, Wi-Fi/mobile handover, and newly available IPv6 during an active connection.
- [ ] Packet capture on real devices: verify blocked-family traffic and DNS do not bypass the intended managed route while active; check helper/LAN exclusions, cancellation, native crash and restoration of routes. Explicitly report post-disconnect behavior, not a kill-switch guarantee.
- [ ] Verify Balanced/Fast, each supported Aether transport, Psiphon, Tor, and Serverless A/B/OOB on reachable real networks. A listener or config-parser success is insufficient.
- [ ] Windscribe issue #2: actual client authentication, system tunnel, independent verified public egress, data transfer, route exclusions/loop prevention, reconnect and disconnect. WStunnel/Stealth handshake tests alone are insufficient.
- [ ] Complete physical-device reconnect, battery/performance, accessibility, signing and third-party notice acceptance from the preceding roadmap.

Track remaining family acceptance in [issue #20](https://github.com/Nishef1/ktest/issues/20). Do not publish a final release based solely on green CI.

### IP-check and Serverless correction (2026-11-23)

- [x] Remove the sole dependency on the one.one.one.one diagnostic hostname. Shared IP/country measurement tries GeoJS (with documented family-specific hostnames), ipapi.co and ordinary Cloudflare web trace; validate the actual returned family and country, keep TLS verification, no proxy-to-direct fallback.
- [x] Remove Android's independent IP display selector. The panel follows the persistent connection family.
- [x] Allow explicit Android VPN coverage for Serverless. The public IP is still the ISP's; Windows remains proxy-only. Run native Xray config preflight and send DNS to the pinned Xray port-53 handler rather than another DoH endpoint that the upstream may block.
- [ ] Verify availability of each IP-check provider and actual Serverless browsing on Iranian mobile/fixed networks, with both VPN and proxy coverage. Non-DNS UDP remains unsupported in the shared Serverless path. Test Android Private DNS interaction and route cleanup; do not claim a foreign exit or working bypass based only on IP-check success.

### TLS calibration application (2026-11-23)

- [x] Apply the exact measured winning tuple to compatible Aether MASQUE H2 profiles and rank successful candidates by measured replies/latency, without an artificial Chrome tolerance.
- [x] Preserve alternate profiles, explicit settings and native HTTPS validation. Show actual selected native TLS configuration in Android and Windows; distinguish configured values from packet-level fingerprints.
- [x] Separate tuned SNI/fragment performance keys from stable native process/profile IDs; report explicit calibration save failures and reject network changes during measurement.
- [ ] Physical-network validation: compare active native ClientHello shape with the simulated probe, verify actual application throughput, stability, and fallback on both devices. Calibrate IPv6 gateways independently; current H2 probe inventory is not a proof for IPv6 or H3.
- [ ] Evaluate pinned Aether core's newer TLS-shaping flags only after actual binary capability and network tests; do not advertise full browser impersonation based on cipher list alone.

### PattNG Aether follow-up

- [x] Preserve Patterniha v2.4.0 release lock; verify archive origin/digests against release metadata.
- [x] Separate simulated H2 IPv4 and IPv6 carrier measurements; do not credit one family with the other's result.
- [x] Reuse an HTTPS-verified native Android candidate when still available for the same core/network/settings; expose saved trial details and strip unmanaged native environment overrides.
- [ ] Native A/B measurement on physical Iranian networks: compare authenticated tunnels and sustained data transfer, validate the actual ClientHello, and record failure rates. Android does not yet offer the full Windows comparison workflow.
- [ ] Investigate advanced v2.4.0 TLS flags (TLS 1.3 suites, groups/key shares, signature algorithms and extension settings) against the pinned core. Do not auto-enable unmeasured options or call cipher-only fingerprints full browser emulation.
