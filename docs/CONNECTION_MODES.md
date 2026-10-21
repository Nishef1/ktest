# ktest connection modes

`ktest connect` defaults to **balanced**: local-first adaptive routing with on-demand exit discovery. There is no AI/TikTok-specific routing rule in current source. For a verified foreign IP, choose Aether to Psiphon or Aether to Tor; the local-only Windscribe mode is not a foreign exit, while Windscribe through Aether requires the actual Windscribe VPN to connect.

Current source/CI evidence and known calibration/performance gaps are tracked in [CURRENT_AUDIT_2026-10-21.md](CURRENT_AUDIT_2026-10-21.md). Mode IDs, canonical titles/details, Android availability and shared routing policy live in `internal/connectionpolicy`; the terminal and Android should consume that catalog rather than maintain independent mode semantics. The two UIs intentionally differ in presentation, while route selection, failure policy and the meaning of connection status must remain aligned.

The menu separates **policy** (1-6) from **coverage** (7). Policies 1-4 and 6 use the selected proxy-app or Whole PC TCP coverage. Option 5 is the Windscribe bridge and always leaves coverage to Windscribe. Select coverage first, then the policy; choosing Whole PC does not launch a second routing policy or silently reset the selected policy to Balanced.

The first Windows launch defaults to TUN; subsequent launches restore the user's saved coverage and connection settings. Other platforms initially use Proxy. Changes are saved when selected, and the last chosen policy is marked without connecting automatically. `connect -tun=false` uses Proxy coverage for that run only; add `-save` to keep a run's flags as the defaults. Windscribe does not overwrite the saved TUN/Proxy choice of other policies.

Use Balanced or Fast for local-first adaptive routing and on-demand exit discovery. **Aether** requires a working WARP carrier for all managed traffic, but that carrier's public IP may geolocate to Iran; Aether is not a foreign-IP guarantee. Use **Aether to Psiphon** or **Aether to Tor** when a verified non-Iran/non-Russia exit is required. Fast excludes Psiphon and Tor. Menu 5 separates the local-only Windscribe bridge from explicit **Windscribe through Aether**. Setup prepares capabilities; it does not silently enable another mode. See [network diagnosis and method selection](NETWORK_DIAGNOSIS.md).

Balanced and Fast connect without a representative website sweep or periodic website probes. Android does not calibrate or freeze targets on Connect. Both begin with Go, ByeDPI, Xray and consented fronting methods and request a shared exit search after local failure or a three-second stall; there is no AI/TikTok-specific immediate-discovery exception. Balanced can fall back to Aether, Psiphon/CDN and Tor. Fast permits native Aether exit transports and excludes Psiphon, Tor and unidentified external SOCKS. Balanced gives WARP, Psiphon/CDN and Tor independent bootstrap slots, without truncating the standalone backends to WARP's short first sweep. Both keep per-network, per-mode route ranking hints for 24 hours and reuse them across reconnects. Both platforms reuse a healthy selected exit/carrier and stop discovery while it remains healthy; no capability promises universal service access.

**Historical field samples (2026-10-19; not a current routing guarantee).** At that time, Psiphon/CDN produced a verified US exit on Windows and Android; a separate Android UID fetched the public TikTok profile through Balanced's HEV TUN in 4.8 seconds and Telegram returned HTTP 200 in 3.5 seconds. X's public profile returned HTTP 200 through consented fronting in Balanced and Fast. An unauthenticated TikTok post-list API request returned HTTP 200 with an empty body, so feed contents and playback were not verified by those samples. Android Fast used permitted packaged Aether exits on demand; Psiphon CDN was Balanced-only.

**Current policy (2026-10-21):** there is no AI/TikTok-specific routing rule. Balanced/Fast treat those hosts like other destinations and may use direct/local paths or on-demand exits. Aether sends managed traffic through WARP even if its IP geolocates to Iran. Psiphon/Tor require a separately verified non-Iran/non-Russia exit. The earlier Android cold-start failures remain historical evidence; current-commit physical-device recovery, authenticated APIs, feeds, media playback and universal service access have not been validated.

CLI policy options:

For TCP-based Aether transports, Fast/Balanced can use an independent private
Go/ByeDPI carrier alongside direct dialing. It reuses local cores and trusted
DNS and is only a bootstrap path for Aether's own outer connection, not a public
foreign exit. Application traffic follows the selected mode: Aether requires a
working WARP carrier but its IP may be in Iran; Balanced/Fast request managed
exits on local failure/stall and have no AI/TikTok exception; Psiphon/Tor require
verified foreign exits. UDP-based WireGuard/HTTP3 transports are never sent into
this TCP-only carrier. Fast's no-Psiphon/Tor boundary also covers fresh WARP
identity registration.

Local TLS or ECH acceptance is insufficient: Aether must establish CONNECT-IP,
carry data and pass independent HTTPS/foreign-exit verification. The sampled
2026-10-19 network reached ECH-capable gateways but also returned CONNECT-IP
400 responses, certificate rejection or timeout; that test did not establish
a usable native WARP exit. These failures are not promoted as working routes.
Community reports posted on 2026-10-21 describe filtering UDP DNS HTTPS-record
queries (type 65) and, on at least one network, blocking the visible SNI
`cloudflare-ech.com`. These are network-specific reports, not a nationwide
measurement. AliDNS DoH reportedly worked on one network, but DoH cannot fix a
separately blocked SNI used by the ECH bootstrap.

KTest's ECH bootstrap is DNS-independent but not SNI-independent: it dials
built-in Cloudflare IP hints over TCP/443 with a deliberately unusable ECH
configuration, then uses the current retry configuration returned by the edge.
The outer public name `cloudflare-ech.com` remains visible, so this bootstrap
can fail when that SNI is filtered. KTest now keeps non-ECH profiles first and
bounds the caller wait; a failed ECH attempt does not suppress IPv4/IPv6
MASQUE H2 or WireGuard candidates. Packet DNS also offers RFC 8484 DoH at
`https://dns.alidns.com/dns-query`, pinned to `223.5.5.5` and `223.6.6.6`
while validating the certificate for `dns.alidns.com`. This is an alternate
resolver path, not proof of access on every ISP.

**PattNG field report (2026-10-21; not independently reproduced by KTest).**
The report describes these candidates:
- MCI/MCI-like firewall: CDN/Worker with IPv6 and an unfiltered personal domain or
  `workers.dev`; WARP/WireGuard over IPv6; or MASQUE HTTP/2.
- Irancell/Irancell-like firewall: CDN/Worker F&F with a candidate Cloudflare IP,
  `tlshello-0-len`, semi-python cipher suites, the Xray `unsafe` fingerprint,
  and ALPN matching the selected WS/XHTTP transport; WARP with either IP family;
  or MASQUE HTTP/2. The report warns that SIM operator and actual firewall can
  differ by region.

KTest now has non-ECH IPv6 candidates for native MASQUE H2 and WireGuard, and
both terminal and Android try IPv4/IPv6 variants within the selected protocol.
KTest's CDN scanner is not a Worker tunnel builder. The repository has a
separate Xray-profile path, but the field summary lacks a complete
server-specific configuration (domain, transport/path, UUID and origin), so it
is not enough to generate a working Worker WS/XHTTP profile. Do not apply
Xray's `unsafe` fingerprint or ALPN settings to Aether's native TLS profiles.
The example IP is a candidate, not a permanent endpoint.

Related X thread: https://x.com/SarinaNeverDies/status/2112978692473311299

ECH registration and ECH-dependent profiles are skipped when the direct
bootstrap itself fails (rechecked every five minutes); use another app's local
proxy or another VPN if that specific path fails (see USAGE.md).
The saved-key check treats only credential-specific refusals (a TLS
access-denied/certificate alert after the handshake, or CONNECT-IP 401/403)
from two gateways as a refused key; CONNECT-IP 400 and 5xx are gateway or
request errors and never cause a key to be set aside.

| Option | Scope | IP policy | Failure policy |
| --- | --- | --- | --- |
| `-mode balanced` | normal mixed access | Sites may use your own IP or an exit, whichever works | Exits are searched for on demand |
| `-mode fast` | local methods first | Direct/ByeDPI/Go/Xray/fronting and Windows Zapret2; native Aether exits | No Psiphon/Tor/unidentified external SOCKS |
| `-mode windscribe` | **strict local-only anti-DPI** HTTP/SOCKS bootstrap for installed Windscribe | OpenVPN TCP re-wrapped in Windscribe WStunnel (chosen SNI; optional own Cloudflare hostname whose origin is a Windscribe server) + local Xray TCP fragmentation + ByeDPI; no Psiphon/Aether/WARP/Tor, foreign/unknown Xray exit or Plain; only Windscribe changes public VPN IP | No foreign fallback. HTTP CONNECT may be acknowledged before the carrier race; a later failure closes that stream. Windscribe Firewall controls other apps |
| `-mode windscribe-aether` | **explicit WARP carrier** for installed Windscribe OpenVPN TCP | Measured Aether MASQUE/WireGuard/nested WARP; no Psiphon/Tor/direct fallback. Carrier may exit in Iran; Windscribe owns the final VPN IP | Requires a live verified carrier and readable Windscribe CLI; keep Aether running and exclude its transport from Windscribe routing. Direct AI requests still require a separate foreign verification |
| `-mode aether` | all managed traffic **sent through ktest's SOCKS/HTTP listeners and a working WARP carrier** | Carrier may geolocate to Iran; no foreign-country guarantee | Fail closed if no usable carrier; no direct fallback |
| `-mode psiphon` | Aether to Psiphon; all managed traffic | Only Aether Psiphon profiles, including CDN fronting; verified foreign exit required | Fail closed; no WARP, Tor, direct or external SOCKS fallback |
| `-mode tor` | all traffic **sent through ktest's SOCKS/HTTP listeners** | Tor-only, may use different exit IPs by circuit/site | Fail closed while Tor is unavailable |

## How to use

```powershell
# Quick access (original behavior for ordinary sites)
go run ./cmd/ktest connect -mode fast

# Balanced, adaptive (default)
go run ./cmd/ktest connect -mode balanced

# Windscribe's LAN HTTP proxy in its Preferences: 127.0.0.1 / 10801
# Windscribe's own actual VPN protocol: OpenVPN TCP/443
go run ./cmd/ktest connect -mode windscribe  # strictly local ByeDPI/packet manipulation, no foreign egress

# Separate explicit WARP carrier; Windscribe still owns VPN authentication/IP
go run ./cmd/ktest connect -mode windscribe-aether

# Verified foreign exit only; Aether/Psiphon is searched in the background
go run ./cmd/ktest connect -mode aether

# Psiphon-only with Aether; tries the normal and CDN Psiphon profiles
go run ./cmd/ktest connect -mode psiphon

# Tor-only with Aether v2's tor feature / automatic bridge discovery
go run ./cmd/ktest connect -mode tor

# Same selected policy, broader TCP coverage; requires Windows Administrator
go run ./cmd/ktest connect -mode aether -tun
```

For modes other than Fast, Windscribe and Aether to Psiphon, an **already running** external SOCKS5 exit can be supplied via `-exit-socks 127.0.0.1:PORT`. **Fast, Windscribe and Aether to Psiphon reject this option.** Aether to Psiphon uses only its managed Psiphon profiles so an unidentified SOCKS proxy cannot substitute another transport. The `Aether to` labels describe which Aether backend is selected; they do not add another VPN hop before Psiphon or Tor. Tor additionally checks that `https://check.torproject.org/api/ip` returns `IsTor: true`, not merely that a proxy is open. Both Tor and other strict exits are checked for non-Iran, non-Russia country before being used for protected routing.

**IMPORTANT:** SOCKS/HTTP proxies do not capture applications that are not configured to use them. `ktest -tun` (whole-PC) is a separate optional Windows route mode. It currently supports TCP and rejects most UDP with ICMP feedback for faster TCP fallback. It is **not an OS-level persistent kill switch**; if ktest crashes, system routes can be restored and traffic might escape. For sensitive use requiring all-app leak prevention, rely on a real VPN plus Windscribe's Firewall or another independently tested system-level lock. **Never run Windscribe alongside ktest's whole-PC TUN**. The Windscribe mode refuses `-tun` and an active `sing-tun` network adapter.

## IP stability and limitations

In **Aether** mode, managed traffic requires a working WARP carrier, but the observed IP/country is not guaranteed to be foreign or static. In **Psiphon/Tor** modes, a selected exit must pass the non-Iran/non-Russia verification policy and traffic fails closed when the required exit is unavailable. A pinned route does not guarantee a pinned public IP: providers can rotate endpoints and Tor changes circuits. The country/IP check has a five-minute lease and is refreshed through a neutral HTTPS endpoint before traffic that requires a verified foreign exit; this is sampled GeoIP evidence, not continuous per-destination geolocation or a cryptographic guarantee.

When a truly stable login/location is necessary (AI sites may trigger extra checks on exit-IP changes), use a fixed Windscribe location, or consider Windscribe's optional Static IP offering. Use Windscribe Firewall when the VPN is active. Tor is designed for anonymity properties, *not* for fixed identity across websites; some services also block Tor exits.

**No AI rule (since 2026-10-21).** The former AI/TikTok policy, together with its switch, `-no-ai-policy` and `-ai-extra`, was removed: it refused AI sites whenever the exit was located in Iran (WARP usually is), which broke Codex and ChatGPT even where they worked. Every site now takes whichever route works in the chosen mode. Whether a service accepts the resulting IP is the user's choice of mode. Psiphon and Tor still send every site through their exit, and Aether still carries every site on a WARP exit.

Hostname routing in Balanced/Fast cannot guarantee a foreign route for a destination whose name is hidden or unavailable. For address-only ECH, KTest can associate the address with names recently resolved through its own DNS and use those names for routing; applications using independent DoH may not provide that association. Only strict foreign-exit modes (Psiphon/Tor) fail closed to a verified foreign exit when the destination remains unknown. Balanced/Fast have no AI/TikTok-specific foreign-exit rule. This policy has source/unit and SOCKS-level coverage, but it has not been validated end to end with a real ECH browser through the Android TUN. For a required foreign IP, use a verified foreign-only mode or a system-wide VPN with an independently tested firewall.

UDP routing follows the selected mode. In Balanced/Fast, non-DNS UDP requires a verified foreign SOCKS5 exit with UDP ASSOCIATE; there is no direct UDP fallback. In Aether, a working WARP carrier may carry managed UDP to any destination even when it geolocates to Iran; this is carrier connectivity, not a foreign-IP guarantee. Psiphon/Tor require verified foreign exits. Aether's own SOCKS5 relays UDP ASSOCIATE through the WARP tunnel (v2.3.2, checked 2026-10-21), so the Windows system tunnel in Aether mode forwards UDP to ktest instead of rejecting it; other modes keep rejecting UDP in the TUN so applications fall back to TCP at once.

Mixed modes do not preselect an ISP route for a silent connection. If an otherwise unprotected destination sends no initial client bytes within two seconds, that connection is closed; use a verified foreign-only mode for server-first protocols. Fragmented TLS ClientHello messages are gathered before hostname/SNI policy is applied.

## Windscribe debugging

See [WINDSCRIBE_BOOTSTRAP.md](WINDSCRIBE_BOOTSTRAP.md). HTTP proxy `127.0.0.1:10801` is separate from Windscribe's destination VPN port. `HTTP CONNECT 200` only proves an initial TCP proxy connection; the VPN's handshake and data plane must also work. New HTTP CONNECT attempts rotate local methods per host:port, independently of API traffic, without interrupting open streams. The supplied 2026-10-16 logs show OpenVPN resets after HTTP 200 and successful Dallas WireGuard with the LAN proxy ignored; that success does not verify ktest's bootstrap. Check for a conflicting whole-PC `sing-tun` adapter, but do not assume one is active.

Never share credentials, auth tokens, private keys or full proprietary Windscribe logs without removing sensitive identifiers.
