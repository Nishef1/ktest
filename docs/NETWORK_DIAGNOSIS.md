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

These names follow the pinned Aether v2.3.0 CLI/runtime, including the distinction between current Gool and classic WARP-in-WARP:

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

Comparison uses two profile workers and a 45-second normal attempt limit; first-use nested tunnels with missing secondary identities may use up to 150 seconds for bootstrap, within the overall comparison budget. Optional transfer sampling downloads at most 128 KiB per working profile, with at most 16 samples (2 MiB of payload total). TLS, tunnel scans and initial identity registration add protocol/network overhead. The result is a **small-transfer observation**, not sustained bandwidth. Cancellation stops temporary cores; unfinished candidates remain untested, rather than being declared blocked.

Measurements live in the per-user WARP directory's `network-measurements.json`. A locally hashed interface/network signature and core SHA-256 isolate networks and core versions. Raw network names, gateways and DNS inventories are not stored. Measurements expire after 24 hours; at most 16 network entries are retained. Corrupt caches are reported and preserved. The cache orders attempts and recommends methods; it cannot authorize a connection or replace live location verification.

Fast weighs latency and any optional transfer sample more strongly. Balanced and strict Aether weigh sample failures more heavily. Normal automatic connection discovery has a 40-second budget, extended to 175 seconds when nested identity bootstrap is pending; explicitly selected methods without pending bootstrap get 65 seconds. Up to three measured exits are retained. A suitable cached foreign winner (or a working carrier in Windscribe-through-Aether) uses a single probe worker first. A failed winner yields to other candidates; recent failed attempts are deprioritized for ten minutes. If no exit is retained, discovery retries with a 30-second, 1-minute, then 2-minute backoff without repeatedly registering the same missing identity in that session. Cancelled Gool outer bootstrap does not mark its inner enrollment attempted.

For active sessions, small neutral health checks run every three minutes only when proxy activity has advanced. Two failed checks retire a core. Discovery resumes when all retained exits have ended. Checks pause while Windscribe reports Connected so an independent probe cannot tear down its working carrier. Protected AI routes remain pinned and fail closed after their selected exit disappears; reconnect to select a new protected identity. Ordinary mixed-mode destinations keep their existing per-host adaptive fallback policy.

## Location and Windscribe boundaries

The neutral probe's IP/country is a sampled observation. Live events distinguish system routes, CDN routes and proxy exits without inventing the exact public IP seen by each destination. A system route may itself pass through another installed VPN. WARP does not promise a foreign country or a static IP.

A working WARP exit in Iran can carry the authenticated Windscribe tunnel in explicit `windscribe-aether` mode. It cannot carry protected ChatGPT/OpenAI, Gemini or Claude requests directly. Strict Aether/Psiphon/Tor require a separately verified non-IR/non-RU exit. Fast/Balanced may use a local-country carrier for ordinary destinations but never as AI fallback. Verification uses a neutral endpoint; no AI request is used to discover whether an untrusted route works.

The normal `windscribe` mode remains local-only. The separate `windscribe-aether` mode excludes Psiphon, Tor, unknown upstream chains, direct routes, fragment routes and website fronting. It forwards raw OpenVPN TCP through a verified WARP carrier; Windscribe owns authentication and final VPN IP. Set Windscribe's HTTP proxy to `127.0.0.1:10801`, select OpenVPN TCP, keep ktest/Aether running, and ensure Windscribe's split-tunnel rules exclude the ktest/Aether helper transport to prevent recursive routing. This mode requires a readable Windscribe CLI state and refuses ktest TUN. A carrier-ready message does not prove a working VPN; use the separate connected-data check.

Standalone comparisons skip an already Connected/Connecting Windscribe session or active ktest TUN, preserve the existing connection, and reject results if network/VPN state changes during measurement. When CLI state is unavailable, the comparison explicitly describes the current system route and cannot claim to measure the bare ISP.

## Identity preparation

Initial registration may be filtered even when gateways work. Existing offline-valid keys are reused; damaged files are kept for explicit repair. Inner identities are prepared only for methods that need them: `wg-secondary.toml` for classic WARP-in-WARP, `masque-secondary.toml` for MASQUE-in-MASQUE, and `masque-gool.toml` for Gool. Gool's inner WireGuard registration travels through a temporary outer MASQUE tunnel. Staged registration validates the exact expected file and publishes without replacing an existing identity. Runtime cores run with automatic reprovisioning disabled. A successful ECH enrollment saves an identity only: it never establishes that a data-plane MASQUE or WireGuard tunnel is reachable. In strict Aether/Psiphon/Tor modes installing a local fronting CA is not a relevant recovery action; CA trust is reserved for explicit website-fronting in mixed modes.

See [connection policies](CONNECTION_MODES.md), [Windscribe tests](WINDSCRIBE_BOOTSTRAP.md), and the authoritative pinned [Aether CLI](https://github.com/CluvexStudio/Aether/blob/v2.3.0/aether/src/cli.rs) / [runtime](https://github.com/CluvexStudio/Aether/blob/v2.3.0/aether/src/lib.rs).
