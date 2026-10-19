# ktest connection modes

`ktest connect` defaults to **balanced**: fastest practical ordinary-site route, but the built-in AI-domain list requires a separately verified non-Iran, non-Russia exit and fails closed if none is available.

The menu separates **policy** (1-6) from **coverage** (7). Policies 1-4 and 6 use the selected proxy-app or Whole PC TCP coverage. Option 5 is the Windscribe bridge and always leaves coverage to Windscribe. Select coverage first, then the policy; choosing Whole PC does not launch a second routing policy or silently reset the selected policy to Balanced.

The first Windows launch defaults to TUN; subsequent launches restore the user's saved coverage and connection settings. Other platforms initially use Proxy. Changes are saved when selected, and the last chosen policy is marked without connecting automatically. `connect -tun=false` selects and remembers Proxy coverage. Windscribe does not overwrite the saved TUN/Proxy choice of other policies.

Use Balanced or Fast for adaptive ordinary-site access with known AI domains and dedicated TikTok domains requiring verified foreign exits in both, Aether when all managed traffic must use a verified foreign WARP/Psiphon exit, Aether to Psiphon for Psiphon profiles only, and Aether to Tor for a verified Tor-only route. Fast gives ordinary-site alternatives a shorter head start; it does not disable AI protection. Menu 5 separates the local-only Windscribe bridge from explicit **Windscribe through Aether**. Setup prepares capabilities; it does not silently enable another mode. See [network diagnosis and method selection](NETWORK_DIAGNOSIS.md).

Balanced and Fast connect without a representative website sweep or periodic website probes. Android does not calibrate or freeze targets on Connect. Manual diagnostics remain available. Their practical differences are route timing (Fast uses a shorter hedge) and measured exit ranking, not a promise of different site coverage.

TikTok page, API, static and media domains use the same verified foreign session route. A locally fast TLS response cannot substitute an ISP path for this service. The observed working option on 2026-10-19 was `-mode psiphon -aether-method psiphon-cdn` (neutral probe country DE, followed by successful TikTok profile and post-list API requests). This is a sampled result, not a guarantee for every network/account. Android Balanced/Fast need an available verified upstream for these domains; otherwise select the managed Aether to Psiphon CDN mode.

CLI policy options:

| Option | Scope | IP policy | Failure policy |
| --- | --- | --- | --- |
| `-mode balanced` | normal mixed access, **AI sites protected** | Ordinary sites may use own IP; AI via verified foreign exit | AI domains stop if foreign exit absent |
| `-mode fast` | faster ordinary-site selection, **AI sites protected** | Ordinary sites may use direct/fragment/fronting/exits; known AI domains require a verified foreign exit | AI fails closed; no ISP-IP fallback for AI |
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

For modes other than Windscribe and Aether to Psiphon, an **already running** external SOCKS5 exit can be supplied via `-exit-socks 127.0.0.1:PORT`. **Windscribe and Aether to Psiphon explicitly reject this option.** Aether to Psiphon uses only its managed Psiphon profiles so an unidentified SOCKS proxy cannot substitute another transport. The `Aether to` labels describe which Aether backend is selected; they do not add another VPN hop before Psiphon or Tor. The Tor-only mode additionally checks that `https://check.torproject.org/api/ip` returns `IsTor: true`, not merely that a proxy is open. Both Tor and other strict exits are checked for non-Iran, non-Russia country before being used for protected routing.

**IMPORTANT:** SOCKS/HTTP proxies do not capture applications that are not configured to use them. `ktest -tun` (whole-PC) is a separate optional Windows route mode. It currently supports TCP and rejects most UDP with ICMP feedback for faster TCP fallback. It is **not an OS-level persistent kill switch**; if ktest crashes, system routes can be restored and traffic might escape. For sensitive use requiring all-app leak prevention, rely on a real VPN plus Windscribe's Firewall or another independently tested system-level lock. **Never run Windscribe alongside ktest's whole-PC TUN**. The Windscribe mode refuses `-tun` and an active `sing-tun` network adapter.

## IP stability and limitations

In the `aether` profile, the first verified foreign exit route that succeeds for a managed connection is pinned for the remainder of the session; other exits are no longer chosen automatically. Known AI domains are protected and pinned in Fast and Balanced too; `-ai-direct` is no longer accepted. The local-only Windscribe bootstrap bridge rejects direct requests to those AI hosts, while Windscribe controls application VPN coverage. A **pinned route does not guarantee a pinned public IP**: Psiphon may rotate servers and Tor changes circuit exits. The country/IP check has a five-minute lease and is refreshed via a neutral HTTPS endpoint before further protected traffic; a failed refresh blocks that traffic. It is not continuous per-destination geolocation or a cryptographic guarantee. Do not claim an identity is fixed based on this.

When a truly stable login/location is necessary (AI sites may trigger extra checks on exit-IP changes), use a fixed Windscribe location, or consider Windscribe's optional Static IP offering. Use Windscribe Firewall when the VPN is active. Tor is designed for anonymity properties, *not* for fixed identity across websites; some services also block Tor exits.

Hostname routing in Fast and Balanced cannot protect what it cannot identify (for example, some opaque IP-only, ECH-without-visible-name, non-proxied, or UDP connections). For sensitive applications, use a verified foreign-only route with their traffic explicitly through ktest, or a system-wide VPN with a real firewall.

Mixed modes do not preselect an ISP route for a silent connection. If an otherwise unprotected destination sends no initial client bytes within two seconds, that connection is closed; use a verified foreign-only mode for server-first protocols. Fragmented TLS ClientHello messages are gathered before hostname/SNI policy is applied.

## Windscribe debugging

See [WINDSCRIBE_BOOTSTRAP.md](WINDSCRIBE_BOOTSTRAP.md). HTTP proxy `127.0.0.1:10801` is separate from Windscribe's destination VPN port. `HTTP CONNECT 200` only proves an initial TCP proxy connection; the VPN's handshake and data plane must also work. New HTTP CONNECT attempts rotate local methods per host:port, independently of API traffic, without interrupting open streams. The supplied 2026-10-16 logs show OpenVPN resets after HTTP 200 and successful Dallas WireGuard with the LAN proxy ignored; that success does not verify ktest's bootstrap. Check for a conflicting whole-PC `sing-tun` adapter, but do not assume one is active.

Never share credentials, auth tokens, private keys or full proprietary Windscribe logs without removing sensitive identifiers.
