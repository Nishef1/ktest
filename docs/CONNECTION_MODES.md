# ktest connection modes

`ktest connect` defaults to **balanced**: fastest practical ordinary-site route, but the built-in AI-domain list requires a separately verified non-Iran, non-Russia exit and fails closed if none is available.

The menu also allows selecting each mode. CLI:

| Option | Scope | IP policy | Failure policy |
| --- | --- | --- | --- |
| `-mode balanced` | normal mixed access, **AI sites protected** | Ordinary sites may use own IP; AI via verified foreign exit | AI domains stop if foreign exit absent |
| `-mode fast` | fastest usable destination path | Direct, fragment, fronting, or Psiphon may win; public IP may differ by destination | Can fall back to local ISP IP |
| `-mode windscribe` | **strict local-only anti-DPI** HTTP/SOCKS bootstrap for installed Windscribe | Generated local Xray TCP fragmentation + ByeDPI; no Psiphon/Aether/WARP/Tor, foreign/unknown Xray exit, Plain or CDN relay; only Windscribe changes public VPN IP | Local TCP methods attempted, fails 502 when unavailable; Windscribe Firewall protects other apps |
| `-mode vpn` | all traffic **sent through ktest's SOCKS/HTTP listeners** | One verified foreign SOCKS path is pinned after its first success in this session | Fail closed; never switch to direct/fragment/fronting |
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

# Verified foreign exit only; Aether/Psiphon is searched in the background
go run ./cmd/ktest connect -mode vpn

# Tor-only with Aether v2's tor feature / automatic bridge discovery
go run ./cmd/ktest connect -mode tor
```

For modes other than Windscribe, an **already running** external SOCKS5 exit can be supplied via `-exit-socks 127.0.0.1:PORT`. **Windscribe mode explicitly rejects this option.** The Tor-only mode additionally checks that `https://check.torproject.org/api/ip` returns `IsTor: true`, not merely that a proxy is open. Both Tor and other strict exits are checked for non-Iran, non-Russia country before being used for protected routing.

**IMPORTANT:** SOCKS/HTTP proxies do not capture applications that are not configured to use them. `ktest -tun` (whole-PC) is a separate optional Windows route mode. It currently supports TCP and drops most UDP. It is **not an OS-level persistent kill switch**; if ktest crashes, system routes can be restored and traffic might escape. For sensitive use requiring all-app leak prevention, rely on a real VPN plus Windscribe's Firewall or another independently tested system-level lock. **Never run Windscribe alongside ktest's whole-PC TUN**. The Windscribe mode refuses `-tun` and an active `sing-tun` network adapter.

## IP stability and limitations

In the `vpn` profile, the first verified foreign exit route that succeeds for a managed connection is pinned for the remainder of the session; other exits are no longer chosen automatically. A **pinned route does not guarantee a pinned public IP**: Psiphon may rotate servers and Tor changes circuit exits. The country/IP check is a one-time HTTPS test, not a continuous per-destination geolocation or cryptographic guarantee. Do not claim an identity is fixed based on this.

When a truly stable login/location is necessary (AI sites may trigger extra checks on exit-IP changes), use a fixed Windscribe location, or consider Windscribe's optional Static IP offering. Use Windscribe Firewall when the VPN is active. Tor is designed for anonymity properties, *not* for fixed identity across websites; some services also block Tor exits.

In `balanced` mode, hostname routing cannot protect what it cannot identify (for example, some opaque IP-only, ECH-without-visible-name, non-proxied, or UDP connections). For sensitive applications, use `vpn` with their traffic explicitly through ktest, or a system-wide VPN with a real firewall.

## Windscribe debugging

See [WINDSCRIBE_BOOTSTRAP.md](WINDSCRIBE_BOOTSTRAP.md). HTTP proxy `127.0.0.1:10801` is separate from Windscribe's destination VPN port. `HTTP CONNECT 200` only proves an initial TCP proxy connection; the VPN's handshake and data plane must also work. New HTTP CONNECT attempts rotate local methods per host:port, independently of API traffic, without interrupting open streams. The supplied 2026-10-16 logs show OpenVPN resets after HTTP 200 and successful Dallas WireGuard with the LAN proxy ignored; that success does not verify ktest's bootstrap. Check for a conflicting whole-PC `sing-tun` adapter, but do not assume one is active.

Never share credentials, auth tokens, private keys or full proprietary Windscribe logs without removing sensitive identifiers.
