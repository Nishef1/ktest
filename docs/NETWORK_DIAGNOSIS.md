# Aether methods and measured network selection

Menu **3 > Aether** offers Connect, Choose method, Compare this network, and Saved recommendations. The method choice is saved. **Diagnose > Aether comparison** runs a bounded comparison; its optional small-transfer variant adds download samples. The command-line equivalent is:

```powershell
ktest aether-test                         # three-minute overall budget
ktest aether-test -budget 5m -speed       # 15s..10m; optional bounded payload
ktest connect -mode fast -aether-method auto
ktest connect -mode aether -aether-method masque-h2
ktest connect -mode windscribe-aether -aether-method gool-h2
```

## Methods

These names follow the Aether v2.3.1 CLI/runtime, including the distinction between current Gool and classic WARP-in-WARP:

| Saved method | Transport |
| --- | --- |
| `auto` | Compatible profiles ordered by this network's measurements |
| `masque-h2` | MASQUE over HTTP/2/TCP, including ECH/fragment variants |
| `masque-h3` | MASQUE over HTTP/3/QUIC |
| `wireguard` | WireGuard, including supported obfuscation variants |
| `gool-h2`, `gool-h3` | WireGuard inside MASQUE H2/H3 (`--gool`) |
| `wiw` | Classic WireGuard inside WireGuard (`--gool-classic`) |
| `mim-h2`, `mim-h3` | MASQUE inside MASQUE H2/H3 (`--mim`) |
| `psiphon`, `psiphon-cdn` | Standalone Psiphon / Psiphon CDN through Aether |

Only methods supported by the installed core's `--help` are launched. The editable `profiles/aether-profiles.txt`, when present, **replaces** built-in profiles; remove unwanted overrides yourself or add the new families there. Forcing a method limits managed discovery to that family. Incompatible saved choices are reset to automatic when changing to Psiphon or Windscribe-through-Aether; explicit incompatible CLI flags are rejected. Tor has its separately verified backend and does not use the WARP comparison.

QUIC is the Aether helper's outer transport. It does not add application UDP support to ktest's TCP-only TUN. Nested tunnels are candidates to measure; extra layers are not inherently faster or more resistant on every ISP.

## Bounded measurement and reuse

Each candidate must carry verified HTTPS to a neutral exit-location endpoint. Strict exit-only Connect modes defer representative site checks entirely until at least one live foreign exit is verified; an unavailable exit is not reported as five failed websites. It then checks YouTube, Google, Wikipedia, Telegram and Discord using the existing lightweight startup probes. These requests contain no user cookies, credentials or AI-service requests; redirects are not followed. No website list or browsing history is saved.

Strict Aether comparison uses one profile worker, matching PattNG's rule against scanning with a live session's shared WARP keys. Each attempt's deadline includes one native gateway scan, the subsequent Aether tunnel startup time and additional exit verification. First-use nested identities receive at least 225 seconds for outer tunnel, enrollment, and inner tunnel, subject to the overall comparison budget; incomplete attempts are not proof of blocking. Optional transfer sampling downloads at most 128 KiB per working profile, with at most 16 samples (2 MiB of payload total). TLS, tunnel scans and initial identity registration add protocol/network overhead. The result is a **small-transfer observation**, not sustained bandwidth. Cancellation stops temporary cores; unfinished candidates remain untested, rather than being declared blocked.

Measurements live in the per-user WARP directory's `network-measurements.json`. A locally hashed interface/network signature and core SHA-256 isolate networks and core versions. Raw network names, gateways and DNS inventories are not stored. Measurements expire after 24 hours; at most 16 network entries are retained. Corrupt caches are reported and preserved. The cache orders attempts and recommends methods; it cannot authorize a connection or replace live location verification.

Fast weighs latency and any optional transfer sample more strongly. Balanced and strict Aether weigh sample failures more heavily. Automatic discovery budgets each wave for its initial workers' scan plus startup and verification, capped at eight minutes. Later deep-scan variants do not inflate the current wave. Strict Aether and Windscribe-through-Aether retain one verified WARP winner and stop scanning while it is healthy; other policies retain their existing capacity. A suitable cached foreign winner (or a working carrier in Windscribe-through-Aether) uses a single probe worker first. A failed winner yields to other candidates; recent failed attempts are deprioritized for ten minutes. If no exit is retained, discovery retries with a 30-second, 1-minute, then 2-minute backoff without repeatedly registering the same missing identity in that session. Cancelled Gool outer bootstrap does not mark its inner enrollment attempted. Aether v2.3.1 includes upstream PR #147, which changes selection and retirement of failing gateways. Like PattNG, KTest now requests quick reconnect: the native core revalidates remembered peers and scans afresh when they fail. An explicit `--no-quick-reconnect` still forces a fresh scan. H2/ECH profiles no longer disable TLS fragmentation.

### Gateway discovery and startup deadlines (2026-10-20)

The pinned core's `--startup-secs` begins **after gateway selection**. Its balanced
MASQUE scan can take 120 seconds; the first balanced WireGuard scan can take 80
seconds, then try other obfuscation profiles. Previously KTest's 65-second
listener timeout, or its 40-second automatic wave, could terminate the core
before even that first scan ended. Shared readiness budgets now include the
scan; they still bound retries and do not promise that every candidate was tried.

The Windows/desktop CLI's automatic `aether` and `windscribe-aether` searches
now use two sweeps. In the first sweep, ordinary MASQUE H2/H3 and WireGuard
profiles without an explicit scan policy use the core's `--scan turbo`:
45 seconds for MASQUE discovery, 30 seconds for WireGuard discovery. Remembered
gateways are still revalidated first, and a selected tunnel still needs the
independent TLS and HTTPS exit checks. Identity preparation and exit verification
retain the original outer allowance. The optional saved-MASQUE-key preflight is
limited to eight seconds during Connect and reports its progress: a timeout
preserves the key and allows the live carrier attempt to proceed. Explicit
diagnostic comparisons retain their existing key-check allowance. Key probes
also reuse the managed Aether runner so an inherited `RUST_LOG=warn` cannot hide
the TLS/CONNECT-IP acceptance markers and cause a false timeout. If the sweep
finds no usable exit, subsequent sweeps restore the profiles' full scan policies.
Nested tunnels, explicit scan
flags/peers, forced methods, and diagnostic comparisons keep their existing
budgets. These are native scan budgets, not measured end-to-end connection times;
cached-peer checks, enrollment and tunnel startup can add time.

During automatic MASQUE discovery, the native core's final `no usable MASQUE
gateway found` result yields to the next profile immediately instead of spending
the remaining startup allowance on the same scan again. A low-level scan timeout
alone does not trigger this transition; WireGuard's internal obfuscation fallbacks
and nested bootstrap remain intact. The change cancels readiness only; an already
selected carrier retains its session lifetime. Strict discovery still uses one
worker and stops scanning while its winner is healthy. This scheduling change is
limited to the desktop CLI; Android's native launcher is unchanged.

Windscribe-through-Aether now has the same live terminal panel as other managed
connections. Its action says to **wait before starting Windscribe** while no WARP
carrier is verified, **connect Windscribe now** as soon as a carrier is ready,
or **wait for Windscribe to finish** when the CLI reports Connecting. A carrier
ready in Iran is sufficient for this step; the user need not wait for a foreign
WARP exit or a complete inventory scan. Unknown CLI status instead asks the user
to check the app before connecting. The panel updates every second and returns
to the waiting instruction if the carrier disappears while Windscribe is
disconnected. Carrier readiness is never labeled as authenticated VPN success.
Both Aether and Windscribe-through-Aether reuse the same per-network/core
measurements: a direct plain-H2 winner from Aether takes priority over failing
ECH variants when launching Windscribe-through-Aether as well.

Following [PattNG's scanner](https://github.com/patterniha/PattNG/blob/my-releases/V2rayNG/app/src/main/java/com/v2ray/ang/core/AetherScanner.kt),
managed runtime logging uses INFO to observe native scan/selection milestones.
An inherited `RUST_LOG=warn` no longer overrides the managed CLI log setting.
The CLI displays the native candidate inventory/budget and validated endpoint
selection, while withholding arbitrary INFO messages from the terminal. A selected
endpoint still needs separate HTTPS/foreign-exit verification. Full native logs
remain local; identities and shell settings are preserved.

Earlier live samples on the system route loaded the existing identities and
completed the first 120-second MASQUE and 80-second WireGuard scans without a
usable endpoint. Forced H2 samples with fresh ECH did not establish a validated
tunnel; a sampled alternate TCP port refused connection. These are bounded
observations, not proof that every endpoint or ISP is blocked. The subsequent
KTest comparison refused to run while Windscribe reported Connecting; no VPN
or system route was changed to bypass that check. At that stage, a bare-ISP
comparison and a successful end-to-end foreign exit remained unverified.

A later supplied Aether session reused plain MASQUE H2 gateway
`162.159.198.8:443` and reported carrier readiness in 4.3 seconds. A controlled
Windscribe-through-Aether run on 2026-10-20 reused the same plain-H2 gateway and
reported carrier readiness in 3.8 seconds after the key-probe logging repair;
the live panel displayed `CARRIER READY - CONNECT WINDSCRIBE NOW`. The neutral
HTTPS measurement reported an IR carrier (8/9 samples), which is sufficient
to carry Windscribe but does not authorize direct protected AI traffic. These
times measure the carrier waiting stage, excluding compilation and initial
Windscribe CLI checks. Windscribe remained Disconnected in that sample, so
authenticated VPN connectivity and a foreign exit were not verified. Temporary
test sessions were stopped without changing Windscribe settings or VPN routes.

The reference inspected was PattNG `89c760c`, whose Aether submodule is
`cfc27c5` (the same v2.3.1 core pinned here). `AetherScanner.kt` launches that
core and parses `selected MASQUE gateway` / `selected WireGuard endpoint`;
`ServerAetherActivity.applyScanResult` stores the discovered host/port, and
`AetherCoreManager.buildArguments` supplies `--peer` on later connections.
The native `prober.rs` / `wg_prober.rs` own the seed/range inventory, sampling,
port order, protocol/data-plane checks and RTT selection. KTest reuses this
native discovery and its validated last-connection cache; it does not maintain
a second IP scanner. PattNG's `AetherSession.disturbedByScanOf` refuses a scan
sharing the active session's identity. Strict KTest WARP modes now likewise
probe serially and keep one healthy winner. This removes concurrent use of
the shared keys as a possible interference source; it was not established as
the cause of the sampled network failures.

For active sessions, small neutral health checks run every three minutes only when proxy activity has advanced. Two failed checks retire a core. Discovery resumes when all retained exits have ended. Checks pause while Windscribe reports Connected so an independent probe cannot tear down its working carrier. Protected AI routes remain pinned and fail closed after their selected exit disappears; reconnect to select a new protected identity. Ordinary mixed-mode destinations keep their existing per-host adaptive fallback policy.

## Location and Windscribe boundaries

The neutral probe's IP/country is a sampled observation. Live events distinguish system routes, CDN routes and proxy exits without inventing the exact public IP seen by each destination. A system route may itself pass through another installed VPN. WARP does not promise a foreign country or a static IP.

A working WARP exit in Iran can carry the authenticated Windscribe tunnel in explicit `windscribe-aether` mode. It cannot carry protected ChatGPT/OpenAI, Gemini or Claude requests directly. Strict Aether/Psiphon/Tor require a separately verified non-IR/non-RU exit. Fast/Balanced may use a local-country carrier for ordinary destinations but never as AI fallback. Verification uses a neutral endpoint; no AI request is used to discover whether an untrusted route works.

The normal `windscribe` mode remains local-only. The separate `windscribe-aether` mode excludes Psiphon, Tor, unknown upstream chains, direct routes, fragment routes and website fronting. It forwards raw OpenVPN TCP through a verified WARP carrier; Windscribe owns authentication and final VPN IP. Set Windscribe's HTTP proxy to `127.0.0.1:10801`, select OpenVPN TCP, keep ktest/Aether running, and ensure Windscribe's split-tunnel rules exclude the ktest/Aether helper transport to prevent recursive routing. This mode requires a readable Windscribe CLI state and refuses ktest TUN. A carrier-ready message does not prove a working VPN; use the separate connected-data check.

Standalone comparisons skip an already Connected/Connecting Windscribe session or active ktest TUN, preserve the existing connection, and reject results if network/VPN state changes during measurement. When CLI state is unavailable, the comparison explicitly describes the current system route and cannot claim to measure the bare ISP.

## Identity preparation

Initial registration may be filtered even when gateways work. A strict-mode proxy listener without a live verified exit is never used as its own registration upstream; prepared identities are allowed to bypass the global enrollment lock so independently runnable profiles are not starved. Existing offline-valid keys are reused; damaged files are kept for explicit repair. Inner identities are prepared only for methods that need them: `wg-secondary.toml` for classic WARP-in-WARP, `masque-secondary.toml` for MASQUE-in-MASQUE, and `masque-gool.toml` for Gool. Gool's inner WireGuard registration travels through a temporary outer MASQUE tunnel. Staged registration validates the exact expected file and publishes without replacing an existing identity. Runtime cores run with automatic reprovisioning disabled. A successful ECH enrollment saves an identity only: it never establishes that a data-plane MASQUE or WireGuard tunnel is reachable. An unreachable exit-location probe is recorded as unverified, not as proof that its country is rejected. In strict Aether/Psiphon/Tor modes installing a local fronting CA is not a relevant recovery action; CA trust is reserved for explicit website-fronting in mixed modes.

See [connection policies](CONNECTION_MODES.md), [Windscribe tests](WINDSCRIBE_BOOTSTRAP.md), and the pinned [Aether CLI](https://github.com/patterniha/Aether/blob/v2.3.1/aether/src/cli.rs) / [runtime](https://github.com/patterniha/Aether/blob/v2.3.1/aether/src/lib.rs).

## Bare-ISP Aether connection (2026-10-20)

Measured on a filtered Iranian fixed line with no VPN; MASQUE H2 now connects.

* **Dead saved key.** 1,209 gateways completed TLS and answered CONNECT-IP 400
  or refused the client certificate: the 10/16 MASQUE key was dead at
  Cloudflare while the file was intact, so it never re-enrolled. ktest now asks
  a fixed gateway once per connection (`aether.ProbeMasqueIdentity`, forced
  `--peer`, judged only after TLS completes) and sets a refused key aside as
  `masque.toml.rejected-<time>` before enrolling a new one.
* **Registration needs ECH, without `--fragment`.** The DPI drops any
  ClientHello naming `api.cloudflareclient.com` and reassembles TCP segments
  and TLS records: Aether's fragmenting, record splitting, 1-byte segments,
  the exit-node and 12 ByeDPI strategies all failed. ECH with ktest's own
  fetched key (outer name `cloudflare-ech.com`, not filtered) registered in
  about 3 s. ECH is now the first enrollment route.
* **No ECH inside the tunnel.** Plain `--masque --h2` found gateways on
  `162.159.198.x:443` at once; with ECH in the MASQUE handshake none passed.
  It is now the first built-in profile.
* **WARP exits in Iran.** Plain MASQUE and Gool both showed `loc=IR` via FRA.
  Like PattNG, Aether mode now accepts such a working exit for ordinary sites
  (`ExitRequired`); AI and TikTok still need a non-Iran exit (`ExitOnly`),
  and the status panel says so.

End to end through ktest's SOCKS: YouTube, Google, Instagram, X, Telegram
Web and Wikipedia returned 200 (exit `104.28.214.161`, `colo=FRA`, `loc=IR`).

## PattNG exit-node (2026-10-20)

PattNG (`89c760c`) never lets the Aether core dial the internet itself. Every
core runs with `--upstream socks5://127.0.0.1:<port>`, a loopback inbound of
its Xray whose `exit-node` outbound is a plain `freedom` outbound carrying the
profile's `finalMask` (`AetherCore.through`, `CoreOutboundBuilder.toOutboundAetherExit`).
The WARP API registration, ECH lookup, gateway scan and the tunnel itself all
leave through that mask; Aether 2.3.1 carries UDP over SOCKS5 UDP ASSOCIATE.

KTest has no Xray, so `internal/exitnode` reproduces that outbound: a loopback
SOCKS5 server (CONNECT and UDP ASSOCIATE) whose sockets carry PattNG's shipped
presets, parsed from the same JSON and ported from patterniha/xray-core
v26.10.19 `finalmask/{fragment,noise}`:

| Preset | Used for | On the wire |
| --- | --- | --- |
| `tlshello-0-len` | `masque-h2`, `gool-h2`, `mim-h2`, WARP API registration | first write split into a 114-byte TCP segment, then 1-byte segments 1 ms apart (11 writes at most) |
| `udp-noise` | `masque-h3`, `gool-h3`, `mim-h3`, `wireguard`, `wiw` | 24 random 1200-1230 byte datagrams, 10 ms apart, before the first datagram to each endpoint and again after 28 s idle |

Xray stacks masks with the first one innermost, so in PattNG's TCP presets the
`tlshello` record-splitting stage receives a 114-byte piece shorter than the
ClientHello record and passes it unchanged; the port keeps that behaviour
rather than "fixing" it. Fast, Balanced and Aether modes add one exit-node
variant after each direct WARP profile (`aether.WithExitNodes`, desktop and
Android Auto); the direct profile stays, Aether's own `--fragment` is dropped
in the variant, and Windscribe-through-Aether remains directly carried. This is
a reproduction of PattNG's method, not evidence that it works on a given ISP.

## Aether core and Android Auto upgrade (2026-10-20)

Desktop core downloads now pin the published `patterniha/Aether` v2.3.1
archives with per-platform SHA-256. Their transport source descends from
`CluvexStudio/Aether` commit `577a4c8`, also used by PattNG, with
MASQUE SNI selection (`www.cloudflare.com` by default), updated WARP
registration, new `--api-address`, and gateway-failure handling. The
setup command upgrades an existing legacy executable when the modern
`--api-address` and `--masque-sni` capabilities are not present.
Saved identities are kept; the new binary still requires a fresh live test.

Android now pins verified v2.3.1 native payloads for ARM64, ARMv7 and
x86_64 in `internal/aether/android-cores.json`. All three archive digests
and the nine contained binary digests were checked through a dedicated
GitHub Actions release-audit run before the manifest changed. The original
Psiphon and Lyrebird helper digests were unchanged.

In standalone Android **Aether Auto**, a failed WARP method no longer
ends the entire attempt at the first supported profile. KTest iterates
independent WARP methods, reusing Aether's own gateway scanning within
each candidate and stopping unsuccessful processes before switching.
The total startup deadline remains bounded; TCP-only Fast carrying
excludes UDP-dependent methods. Strict foreign-exit verification remains
separate from native process and SOCKS readiness. Balanced/Fast already
have their own independent native exit discovery.

This is source and artifact-integrity evidence, not proof of successful
WARP egress on an Iranian ISP. Validate native CONNECT-IP, real HTTPS
through the selected SOCKS, Windscribe carrier feasibility, TUN, DNS, UDP
and end-to-end country/IP before considering the upgrade operational.

## Historical upstream limitations (2026-10-17)

The published Aether 2.3.0 may re-enable WARP via a filtered API on each MASQUE startup even with a saved identity. CluvexStudio/Aether #147 fixes this in newer source, not in the previously pinned v2.3.0 artifact. This historical finding motivated the 2026-10-20 upgrade above. Increasing ktest timeouts cannot solve a blocked API. The newer published archives are now pinned and verified separately; a release digest alone does not prove network compatibility. The upstream TLS verification default is off; --tls-verify is supported but should be validated against the intended Cloudflare TLS endpoint before enabling for all methods. Preserve a fail-closed verified-foreign-exit policy regardless of the upstream core's exit-location claim.

### Native-only Windows investigation (2026-10-19)

A bounded comparison on the current Windows system route found **no verified
native Aether exit**. Psiphon and Tor were disabled throughout. This is a
sample of this route at this time, not evidence that every gateway or another
ISP is blocked. Android was not exercised in this investigation.

The published [v2.3.0](https://github.com/CluvexStudio/Aether/releases/tag/v2.3.0)
was compared with an isolated build of upstream
[`577a4c8`](https://github.com/CluvexStudio/Aether/commit/577a4c8dd18b08ddfdc3ad28a92e356d68cfa27c),
including [PR #147](https://github.com/CluvexStudio/Aether/pull/147), built with
`--no-default-features`. Fresh identities, settings and listeners were kept
outside the user's configuration. The production core was not replaced.

| Stage / candidate | Observed result |
| --- | --- |
| Fresh MASQUE and WireGuard registration over ECH | Succeeded without Psiphon/Tor; the newer core also enabled WARP before saving the identities |
| Published v2.3.0 native H2/ECH, H3/ECH and aggressive WireGuard samples | No validated SOCKS exit within the comparison budget; unfinished candidates remain untested |
| Ordinary `www.cloudflare.com` TLS on `162.159.197.1:443` | Certificate-verified HTTPS succeeded; the native MASQUE SNI on the same address timed out before TLS |
| Newer H2 core, native MASQUE SNI with ECH, gateways `162.159.197.1:443` and `162.159.199.1:443` | ECH accepted and TLS/H2 completed, then CONNECT-IP returned HTTP 400; no tunnel |
| Newer H2 core over the local Go/ByeDPI carrier | TLS/H2 completed, then CONNECT-IP returned HTTP 400 on both sampled gateways; no tunnel |
| Alternative H2 SNI (`www.cloudflare.com`, `cloudflareaccess.com`) | TLS/H2 completed in the tested cases, then CONNECT-IP returned HTTP 400 |
| Local Xray freedom / TLS fragmentation carrier | TLS handshake ended before tunnel validation |
| Newer H3/ECH and obfuscated WireGuard samples | No validated SOCKS exit within their bounded attempts |

An additional H2/ECH attempt with `--tls-verify` failed the core's certificate
verification. Therefore the HTTP 400 responses seen with upstream's default
outer TLS policy do not authenticate the responding gateway. They do not by
themselves identify DPI, a server-side rejection, or stale certificate pins.
No end-to-end HTTPS certificate check was disabled to obtain a passing result.

ECH can recover **registration** and some outer TLS handshakes here; neither
proves a working WARP data path. More timeout or a different SNI alone is not
a demonstrated repair. Before adopting the newer core, require CONNECT-IP
acceptance and real certificate-verified HTTPS through its SOCKS listener,
then validate exit policy separately. Its CLI is also incompatible with some
2.3.0 profiles (`--api-address` replaces `--enroll-address`, and some fragment
flags were removed), so replacing the binary alone is not a safe update.
Nested Gool/MASQUE variants were not independently validated; they still need
their outer native tunnel to work.

## Windows TUN privacy boundary and process isolation

The whole-PC Windows TUN currently uses `strict_route=false` to keep its physical bootstrap DNS resolver usable. This **does not provide a DNS kill switch**, and Windows may send DNS queries on another physical network interface. A successful TCP system-route probe cannot prove DNS privacy, IPv6 privacy, or UDP tunneling. sing-box documents `strict_route` as a Windows DNS-leak safeguard but also warns of application compatibility problems; do not blindly enable it without replacing the helper bootstrap resolver and verifying behavior across connect/disconnect, sleep, VPN changes and dual-stack networks.

The running ktest executable and its bundled helpers are exempted using their executable **paths**, not just process names. On Windows tracked subprocesses use kill-on-close Job Objects so their descendants cannot normally outlive a completed helper. An already-running unrelated VPN is not automatically controlled by these cleanup rules.

Aether v2.3.0 automatic component installation selects checksum-pinned Windows x64 ZIP, Linux x64/ARM64 tarballs or macOS x64/ARM64 tarballs. Archive extraction allows only the main executable and known pt/ helpers. Other ktest components, especially the Windows TUN and Windscribe CLI integration, remain platform-specific; a passing cross-compile is not equivalent to full feature parity.

### Windscribe OpenVPN TCP carrier retry policy (October 2026)

For each Windscribe CONNECT attempt, the bridge rotates only provider-advertised IPs and configured SNI/transport variants, with a maximum of 24 outer carrier attempts. Failed TCP/TLS/WebSocket/OpenVPN reply stages receive a temporary per-carrier cooldown; losing candidates cancelled because another carrier succeeded are not classified as blocked. The bridge never claims an OpenVPN-shaped packet authenticates the VPN. A carrier gains priority as soon as the official Windscribe CLI transitions to TCP Connected **while it is the only active OpenVPN stream**. Multiple overlapping streams or missing CLI state remain inconclusive, not successes. Unconfirmed streams which stop early in the approximately 20–30 second handshake failure window receive only a short cooldown and will be eligible again. An authenticated short session is not misclassified as a failure. The log separates client-to-server write failure, upstream read ending, and observed session lifetime; EOF alone is **not** evidence of DPI interference.

The published [Windscribe Android port map](https://github.com/Windscribe/Android-App/blob/main/base/src/main/res/raw/port_map.txt) uses `ip2` for ordinary OpenVPN TCP and `ip3` for **Stealth**. ktest therefore attempts Stealth only on the matching `ip3` entries of a verified node list, never its generic `ip` interface; WStunnel alternatives remain explicitly exploratory until its current authenticated protocol-to-IP mapping can be obtained. Raw OpenVPN keeps Windscribe's originally selected TCP destination. Outer TLS choices and initial OpenVPN packets are **not** proof of a valid VPN session.

These changes correct local retry and transport handling, **not proof of bypassing DPI** or of increased connection success on any particular ISP.

### Tested outer TLS fallback (October 17, 2026)

Direct WStunnel/Stealth candidates now retain the existing Chrome ClientHello and add a separately scored Windscribe-style randomized ClientHello, as the official [Windscribe/wstunnel client](https://github.com/Windscribe/wstunnel/blob/main/cli/httpClient.go) uses randomized ALPN handshakes. The pinned uTLS 1.8.2 can fail on advertised unsupported post-quantum key-exchange groups ([uTLS issue #366](https://github.com/refraction-networking/utls/issues/366)); therefore the randomized alternative restricts its groups to supported X25519/P-256/P-384 and offers only HTTP/1.1 where WebSocket upgrade is required. This is deliberately **not an exact copy of the upstream fingerprint**. The two alternatives are independently measured, preserve the 24-candidate per-attempt cap and do not alter successful in-flight streams. Local TLS/WebSocket regression tests verify framing, not live DPI bypass.

The direct WStunnel outer TLS callback checks only for a Windscribe node-name hint, **not** for a trusted certificate chain. Accordingly, `certificate_verified` in the WStunnel probe is true only after standard TLS certificate verification, not merely because a custom callback accepted the leaf. Stealth carries raw OpenVPN over TLS and preserves the randomized uTLS ALPN offer; only the WebSocket Upgrade transport restricts ALPN to HTTP/1.1. Neither an outer TLS handshake nor a WebSocket HTTP 101 response proves authenticated Windscribe VPN data. The actual OpenVPN connection remains the security boundary for direct Windscribe wrappers.

### Windscribe bridge audit: catalog and framing (October 17, 2026)

- Catalog retrieval now requests Windscribe's **mob-v2** public server lists (`0` and `1` with a current Unix timestamp), keeping the legacy `serverlist/openvpn` paths as fallbacks. The parser accepts both older `data[].nodes` and the newer `data[].groups[].nodes` hierarchy. Empty groups are expected, not evidence that the entire catalog is corrupt. If neither provider endpoint is reachable, a fresh validated local cache may still be used; ktest does **not** guess neighbouring IPs or fabricate missing premium/private server nodes.
- The `ip3` Stealth role is retrieved independently of general-address deduplication. Two provider fields can legitimately reference the same IP; deduplicating by IP alone must not delete its transport role.
- Current provider node hostnames may end in `.whiskergalaxy.com` as well as the historical `.windscribe.com`. The outer TLS name filter recognizes both; **this is not public-key infrastructure certificate-chain verification** when the transport uses a customized SNI. The authenticated OpenVPN tunnel must still perform its own certificate and VPN checks.
- WebSocket upgrade headers have a 16 KiB response bound, check `Connection: Upgrade`, and preserve bytes buffered after the response. Both the HTTP upgrade and subsequent masked WebSocket frames handle short successful writes. Malformed server frame flags and fragment ordering are rejected; remote Close does not block an unlimited control write.
- The official Windscribe CLI must not automatically reconnect until the configured local HTTP CONNECT listener is bound. HTTP 200 confirms the *local* proxy accepted CONNECT; it **does not** establish the Windscribe VPN.
- The bridge still selects the first structurally valid OpenVPN server control response before the Windscribe client can authenticate the handshake. Replacing an established stream with another IP halfway through the TLS handshake is not safe. Ranking improvements therefore apply to the **next** CONNECT, not an in-place failover.
- A green unit-test matrix validates local logic and TLS/WSS framing, not which foreign country is reachable from a particular network. Proving success requires a controlled before/after run using the same target locations with Windscribe's actual Connected state and independently observed exit IP. Detailed logs may contain local IPs and account metadata; redact them before publication.
## DNS transport failures on Android

Encrypted DNS is a candidate path, not a guarantee. Resolver IPs, DoH/DoT
protocols, TLS/SNI, ECH bootstrap, TCP/443 and the carrying tunnel may all be
filtered or unavailable. A timeout alone does not identify which boundary
failed, and does not prove that the destination or Internet is down.

The Android packet-DNS path uses the existing Go transports and reports its
failures separately from connection/listener state. It hedges across wire-DoH
endpoints rather than waiting for one dead endpoint to consume the budget.
Foreign-exit modes keep DNS inside the verified exit; they never silently
switch to ISP DNS or a direct ECH connection. DoT is not currently implemented
as an alternative. Balanced/Fast retain the existing trusted system-first
policy for hostname resolution; that is distinct from packet DNS.

| Observation | Possible causes, not a diagnosis | Next bounded check |
| --- | --- | --- |
| Resolver TCP connection times out | Resolver IP/port filtering, route loss, dead carrier | Compare another existing endpoint and inspect carrier health |
| TCP succeeds, TLS fails | SNI filtering, certificate rejection, interference or server behavior | Preserve certificate checks; compare an existing ECH or tunneled path |
| TLS succeeds, DNS HTTP request fails | DoH endpoint/protocol policy, HTTP rejection, invalid response | Record HTTP/error stage; compare an independent endpoint |
| DoH fails but a verified exit works | Resolver-specific or transport-specific restriction remains plausible | Test DNS inside that exit; do not change exit-only policy |
| All tested encrypted DNS paths fail | Shared network failure or several independently blocked methods | Mark DNS unavailable within this budget; try an existing independent transport explicitly |

These checks must distinguish **failed**, **not attempted**, and **not
validated**. Never turn resolver failure into an automatic second VPN, a
hidden foreign exit in local Windscribe mode, disabled TLS validation, or a
claim that an untested method is blocked.

### Android endpoint check and VPN coverage (2026-10-19)

`Check HTTPS endpoints` checks the eight representative URLs through the active
Go SOCKS listener. It now has a 30-second shared budget with three workers and
a per-request share reserved for later waves. Three silent destinations must
not prevent Discord and X from being attempted. With fronting active, this
internal diagnostic explicitly trusts the session's existing constrained public
CA, as manual route diagnostics do; certificate and hostname verification stay
enabled. The result explains that other Android apps may reject that CA.

On `KTest_API_35` / `emulator-5556`, the reproduced result changed from two
successful requests, four failures and two skipped requests to five successful
requests and three timeouts. YouTube, Google, Instagram, Discord and X passed;
Telegram, Telegram Web and TikTok timed out. This is partial recovery, not
all-site acceptance or proof that a foreign exit is available.

VPN and Both request the same device-wide Android VPN route; Both also offers
the local proxy. KTest's own UID is excluded to avoid routing its outbound
sockets back into itself. The independent VPN probe app uses a separate UID.
With the updated app, that probe observed an active VPN and passed system DNS,
UDP DNS, Cloudflare HTTPS, Google HTTPS and UDP STUN. Cloudflare reported an IR
exit: device-wide interception does not imply a foreign VPN exit in Balanced.
On this emulator, Android installed an unreachable IPv6 default route rather
than a working IPv6 route. The probe must exclude unreachable routes when
deciding whether IPv6 HTTPS should be tested. These samples do not establish
support for every application's UDP traffic or native-app certificate policy.
