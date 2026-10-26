# Windscribe Windows audit — 2026-10-26

## Integration boundaries

- Windscribe's installed Windows app controls VPN authentication, location, firewall, routing and public exit IP. KTest never treats its own SOCKS listener, a WebSocket 101 or an OpenVPN-shaped reply as authenticated VPN success.
- The local bridge wraps the **requested exact Windscribe OpenVPN TCP/443 node**. Candidate WStunnel/Stealth SNI, TLS hello, local ByeDPI/Xray, optional Zapret2 and *user-owned* CDN fronts are tried adaptively. It does not replace Windscribe's chosen city/country with a guessed neighbor IP.
- Provider node inventory is checked against the exact requested node, with a bounded wait and multiple source fallbacks. Only unique, CLI-correlated TCP Connected events promote a carrier; independent HTTPS exit checks remain a separate diagnostic.
- KTest offers encrypted DoH where applicable; Windscribe's own VPN/DNS remain under the installed app. A CDN IP is useful for Windscribe only if the **user configured an actual hostname that can carry the WStunnel upgrade**. Fast general Cloudflare IPs are not interchangeable with authenticated Windscribe nodes or a working CDN front.
- MASQUE SNI/fingerprint/fragment calibration applies to Aether, not Windscribe. Windscribe uses its own transport-specific candidate selection, packet desync strategies and verified control response. Do not overwrite one protocol's tuning with another's.

## Defect fixed: Windscribe proxy ports

Windows Windscribe has always instructed the user to set Windscribe HTTP Proxy Settings to 127.0.0.1:10801, and KTest local SOCKS to 127.0.0.1:10800. Previously, if stock ports were taken by another process, KTest transparently moved to randomly allocated ports while the Windscribe setup panel still showed 10801. This could cause a failed or misleading VPN handshake.

Both Windscribe local and Windscribe-through-Aether sessions now reject a busy listener **without changing the endpoint**. A custom `-listen` or `-http-listen` is still accepted if chosen explicitly; the user must update the corresponding application proxy setting. Other KTest modes keep existing port recovery behavior. No process/port is forcibly closed.

## Verification limits

Portable build, Go unit and race tests are mandatory. An actual Windows Windscribe app + Windows adapter + Iranian ISP network run is not represented by CI. Test login, selected OpenVPN TCP endpoint, HTTP Proxy Settings, intentional disconnect, traffic through the VPN, DNS leak prevention and system HTTPS IP verification before calling the integration field-verified.

## HTTP proxy isolation

The HTTP listener accepts CONNECT requests without a password. Any non-loopback bind (`0.0.0.0`, `::`, LAN/public addresses) is rejected to prevent exposing it as an open proxy. Windscribe local and through-Aether modes also reject port 0 and privileged ports. The Windscribe setup panel shows the actual configured HTTP address when an explicit custom port is used; it is not hard-coded to 10801. Local diagnostics and other modes keep ephemeral loopback-port support when explicitly requested.

## Account API circular-bootstrap regression

When Windscribe CLI itself replies with `Login state: Error: SSL error` (or another explicit API error) and omits its connection state, the previous Aether mode stopped **before Aether was ever started**. This is a bootstrap circularity on restricted networks where a usable network path may need to come before the account API. A missing CLI executable, failed IPC command, ordinary logout, unrecognized response, VPN adapter already up, or connected/connecting/pending indication still fails closed.

A limited, *Aether-carrier-only* bootstrap is now permitted after repeated API-only CLI responses with no active VPN adapter. No Windscribe VPN session is claimed, no automatic reconnect is allowed, and the user must check the Windscribe app before connecting. This is not a bypass for uncertain live VPN states. The monitor continues polling so successful local state reads can transition the UI normally. This does not prove successful Aether network traversal or that Windscribe API traffic will use the carrier.
