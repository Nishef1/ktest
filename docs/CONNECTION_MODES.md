# ktest connection modes

`ktest connect` defaults to **balanced**: fastest practical ordinary-site route, but the built-in AI-domain list requires a separately verified non-Iran, non-Russia exit and fails closed if none is available.

The menu separates **policy** (1-6) from **coverage** (7). Policies 1-4 and 6 use the selected proxy-app or Whole PC TCP coverage. Option 5 is the Windscribe bridge and always leaves coverage to Windscribe. Select coverage first, then the policy; choosing Whole PC does not launch a second routing policy or silently reset the selected policy to Balanced.

The first Windows launch defaults to TUN; subsequent launches restore the user's saved coverage and connection settings. Other platforms initially use Proxy. Changes are saved when selected, and the last chosen policy is marked without connecting automatically. `connect -tun=false` uses Proxy coverage for that run only; add `-save` to keep a run's flags as the defaults. Windscribe does not overwrite the saved TUN/Proxy choice of other policies.

Use Balanced or Fast for adaptive ordinary-site access with known AI domains and dedicated TikTok domains requiring verified foreign exits in both, Aether when all managed traffic must use a verified foreign WARP/Psiphon exit, Aether to Psiphon for Psiphon profiles only, and Aether to Tor for a verified Tor-only route. Fast gives ordinary-site alternatives a shorter head start; it does not disable AI protection. Menu 5 separates the local-only Windscribe bridge from explicit **Windscribe through Aether**. Setup prepares capabilities; it does not silently enable another mode. See [network diagnosis and method selection](NETWORK_DIAGNOSIS.md).

Balanced and Fast connect without a representative website sweep or periodic website probes. Android does not calibrate or freeze targets on Connect. Both begin with Go, ByeDPI, Xray and consented fronting methods and request a shared exit search after local failure or a three-second stall; protected sites request one immediately. Balanced can fall back to Aether, Psiphon/CDN and Tor. Fast permits native Aether exit transports and excludes Psiphon, Tor and unidentified external SOCKS. Balanced gives WARP, Psiphon/CDN and Tor independent bootstrap slots, without truncating the standalone backends to WARP's short first sweep. Both keep per-network, per-mode route ranking hints for 24 hours and reuse them across reconnects. Both platforms keep one verified automatic exit and stop discovery while it is healthy; no capability promises universal service access.

TikTok page, API, static and media domains use the same verified foreign session route. A locally fast TLS response cannot substitute an ISP path for this service. On 2026-10-19, Psiphon/CDN produced a verified US exit on Windows and Android. A separate Android UID fetched the public TikTok profile through Balanced's actual HEV TUN in 4.8 seconds; Telegram returned HTTP 200 in 3.5 seconds. X's public profile returned HTTP 200 through consented fronting in Balanced and Fast, including after a Fast disconnect/reconnect. These are sampled transport/page results: an unauthenticated TikTok post-list API request returned HTTP 200 with an empty body, so feed contents and playback remain unverified. Android Fast uses the permitted packaged Aether exits on demand; Psiphon CDN remains Balanced-only.

Repeated Android cold starts were inconsistent: a later reconnect did not re-establish a verified exit before the TikTok request timed out. Native WARP/Tor and stable automatic exit recovery remain unverified on this network. The successful page samples do not establish full Windows/Android parity, authenticated X APIs, native-app CA acceptance or universal service access.

CLI policy options:

For TCP-based Aether transports, Fast/Balanced also try an independent private
Go/ByeDPI carrier alongside direct dialing. The carrier reuses existing local
cores and trusted DNS, disables foreign discovery, excludes Xray and TLS
takeovers, and preserves the original selected gateway IP while learning by
SNI. The Aether policy can use the same local techniques for its own transport;
managed application traffic still requires a verified foreign exit. UDP-based
WireGuard/HTTP3 transports are never sent into this TCP-only carrier. Fast's
no-Psiphon/Tor boundary also covers fresh WARP identity registration.

Local TLS or ECH acceptance is insufficient: Aether must establish CONNECT-IP,
carry data and pass independent HTTPS/foreign-exit verification. The sampled
2026-10-19 network reached ECH-capable gateways but also returned CONNECT-IP
400 responses, certificate rejection or timeout; that test did not establish
a usable native WARP exit. These failures are not promoted as working routes.
Since 2026-10-21 `cloudflare-ech.com` is reported blocked everywhere in Iran;
ECH registration and ECH-dependent profiles are skipped once the shared
bootstrap fails (rechecked every five minutes), and a first key is obtained
through another app's local proxy or another VPN (see USAGE.md).
The saved-key check treats only credential-specific refusals (a TLS
access-denied/certificate alert after the handshake, or CONNECT-IP 401/403)
from two gateways as a refused key; CONNECT-IP 400 and 5xx are gateway or
request errors and never cause a key to be set aside.

| Option | Scope | IP policy | Failure policy |
| --- | --- | --- | --- |
| `-mode balanced` | normal mixed access, **AI sites protected** | Ordinary sites may use own IP; AI via verified foreign exit | AI domains stop if foreign exit absent |
| `-mode fast` | local methods first, **AI sites protected** | Direct/ByeDPI/Go/Xray/fronting and Windows Zapret2; native Aether foreign exits | No Psiphon/Tor/unidentified external SOCKS; protected sites fail closed without a verified foreign exit |
| `-mode windscribe` | **strict local-only anti-DPI** HTTP/SOCKS bootstrap for installed Windscribe | OpenVPN TCP re-wrapped in Windscribe WStunnel (chosen SNI; optional own Cloudflare hostname whose origin is a Windscribe server) + local Xray TCP fragmentation + ByeDPI; no Psiphon/Aether/WARP/Tor, foreign/unknown Xray exit or Plain; only Windscribe changes public VPN IP | No foreign fallback. HTTP CONNECT may be acknowledged before the carrier race; a later failure closes that stream. Windscribe Firewall controls other apps |
| `-mode windscribe-aether` | **explicit WARP carrier** for installed Windscribe OpenVPN TCP | Measured Aether MASQUE/WireGuard/nested WARP; no Psiphon/Tor/direct fallback. Carrier may exit in Iran; Windscribe owns the final VPN IP | Requires a live verified carrier and readable Windscribe CLI; keep Aether running and exclude its transport from Windscribe routing. Direct AI requests still require a separate foreign verification |
| `-mode aether` | all traffic **sent through ktest's SOCKS/HTTP listeners** | One verified foreign SOCKS path is pinned after its first success in this session | Fail closed; never switch to direct/fragment/fronting |
| `-mode psiphon` | Aether to Psiphon; all managed traffic | Only Aether Psiphon profiles, including CDN fronting; verified foreign exit required | Fail closed; no WARP, Tor, direct or external SOCKS fallback |
| `-mode tor` | all traffic **sent through ktest's SOCKS/HTTP listeners** | Tor-only, may use different exit IPs by circuit/site | Fail closed while Tor is unavailable |

## How to use

```powershell
# Quick access (original behavior for ordinary sites)
go run ./cmd/ktest connect -mode fast

# Balanced, AI fail-closed, other websites adaptive (default)
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

In the `aether` profile, the first verified foreign exit route that succeeds for a managed connection is pinned for the remainder of the session; other exits are no longer chosen automatically. Fast and Balanced keep healthy protected exits pinned, but can select another verified exit after removal of a dead core. `-ai-direct` is no longer accepted. The local-only Windscribe bootstrap bridge rejects direct requests to those AI hosts, while Windscribe controls application VPN coverage. A **pinned route does not guarantee a pinned public IP**: Psiphon may rotate servers and Tor changes circuit exits. The country/IP check has a five-minute lease and is refreshed via a neutral HTTPS endpoint before further protected traffic; a failed refresh blocks that traffic. It is not continuous per-destination geolocation or a cryptographic guarantee. Do not claim an identity is fixed based on this.

When a truly stable login/location is necessary (AI sites may trigger extra checks on exit-IP changes), use a fixed Windscribe location, or consider Windscribe's optional Static IP offering. Use Windscribe Firewall when the VPN is active. Tor is designed for anonymity properties, *not* for fixed identity across websites; some services also block Tor exits.

Hostname routing in Fast and Balanced cannot protect what it cannot identify (for example, some opaque IP-only, non-proxied, or UDP connections). An address-only TLS connection that offers Encrypted Client Hello (its outer SNI is only the provider's public name, e.g. `cloudflare-ech.com`) is routed by the names ktest's own DNS recently resolved to that address: protected if any of them is protected (shared CDN addresses included), and protected by default when no name is known (fail closed onto the foreign exit; in local-only Windscribe it keeps its local route). Applications that resolve through their own DoH therefore send ECH connections to the foreign exit. This is a source-level policy with unit and SOCKS-level tests; it has not been validated end to end with a real ECH browser through the Android TUN. For sensitive applications, use a verified foreign-only route with their traffic explicitly through ktest, or a system-wide VPN with a real firewall.

UDP follows the same identity rule. In Balanced/Fast, non-DNS UDP still needs a verified foreign SOCKS5 exit with UDP ASSOCIATE. In Aether, where a working WARP carrier may carry ordinary websites even when it geolocates to Iran, UDP (e.g. QUIC) may also use that carrier, but only for a destination known not to be protected: a named destination, or an address whose resolved names are all ordinary. Unknown addresses and protected names keep the foreign-exit rule; there is never a direct UDP fallback.

Mixed modes do not preselect an ISP route for a silent connection. If an otherwise unprotected destination sends no initial client bytes within two seconds, that connection is closed; use a verified foreign-only mode for server-first protocols. Fragmented TLS ClientHello messages are gathered before hostname/SNI policy is applied.

## Windscribe debugging

See [WINDSCRIBE_BOOTSTRAP.md](WINDSCRIBE_BOOTSTRAP.md). HTTP proxy `127.0.0.1:10801` is separate from Windscribe's destination VPN port. `HTTP CONNECT 200` only proves an initial TCP proxy connection; the VPN's handshake and data plane must also work. New HTTP CONNECT attempts rotate local methods per host:port, independently of API traffic, without interrupting open streams. The supplied 2026-10-16 logs show OpenVPN resets after HTTP 200 and successful Dallas WireGuard with the LAN proxy ignored; that success does not verify ktest's bootstrap. Check for a conflicting whole-PC `sing-tun` adapter, but do not assume one is active.

Never share credentials, auth tokens, private keys or full proprietary Windscribe logs without removing sensitive identifiers.
