# Windscribe bootstrap with ktest

The goal is **not** to replace Windscribe. It is to give the installed Windscribe desktop client an initial TCP path through ktest's existing censorship-circumvention methods. Once Windscribe establishes its own tunnel, Windscribe is the primary VPN and supplies the external IP.

## Important diagnosis from the October 16 Windscribe log

- An OpenVPN TCP CONNECT to the HTTP proxy received `HTTP/1.1 200 Connection Established`, **but OpenVPN did not complete a tunnel**; it waited and received a connection reset. This means the proxy listener worked, not that the Windscribe server IP was reachable for a VPN handshake.
- A `sing-tun Tunnel` adapter was the Windows default route. This is ktest whole-PC mode and **must be stopped before using Windscribe**; the `windscribe` profile now refuses an active ktest sing-tun.
- Windscribe explicitly logged `LAN proxy setting ignored because the connection protocol is not TCP` for its WireGuard attempt. TCP/443 OpenVPN, Stealth or WStunnel must be tested separately.
- **HTTP** refers to how Windscribe connects to ktest on `127.0.0.1:10801`. It does **not** imply that Windscribe's actual server port should be 80: for WStunnel and the first OpenVPN TCP test, use 443.

Run `ktest connect -mode windscribe` (without `-tun`) and make sure a real foreign exit comes up if the Windscribe server's IP is filtered. If no exit is ready, an HTTP CONNECT success alone is insufficient. Keep Windscribe Firewall in Automatic for initial troubleshooting, and use its own Always On only when the bootstrap/reconnect path has been verified. The ktest app does not manage Windscribe's firewall.

## Start ktest first

Run from an extracted portable release, with Windscribe disconnected:

```powershell
.\ktest.exe connect
```

Connect now exposes two **loopback-only** listeners:

| Listener | Address | Consumer |
| --- | --- | --- |
| SOCKS5 | `127.0.0.1:10800` | Browsers and other SOCKS5-aware apps (remote DNS) |
| HTTP proxy | `127.0.0.1:10801` | Windscribe's **Proxy Settings** or other HTTP proxy-aware apps |

The HTTP listener uses the very same adaptive SOCKS5 route selector as Connect. It adds no DNS, system proxy, routes, certificate, or firewall changes on its own. It does **not** automatically install or change Windscribe.

If `10801` is in use, SOCKS5 still works and Connect reports that the HTTP proxy is unavailable. Use `ktest connect -http-listen 127.0.0.1:10802` to choose another local port. `-no-http` disables the HTTP listener.

## Configure Windscribe (Windows desktop)

1. Open **Preferences -> Connection -> Proxy Settings** in Windscribe. This is the upstream/LAN proxy setting, **not Proxy Gateway** (which shares an *already established* VPN with other devices).
2. Set **HTTP proxy** host to `127.0.0.1` and port to `10801` (or the port printed by ktest). No username or password is required for this loopback-only proxy.
3. Enable **Circumvent Censorship**, then try **Manual -> WStunnel -> 443**. If that fails, try **Stealth -> 443**, then **OpenVPN TCP -> 443**. The exact protocols compatible with the upstream proxy depend on the Windscribe client version and need to be verified using its connection logs.
4. Keep ktest running **for as long as Windscribe relies on the upstream proxy**. Do not use ktest's `-tun` option for this first experiment.
5. To prevent a VPN-over-itself loop when Windscribe connects, configure Windscribe's **Exclude** split-tunneling for the ktest executable and any helper core it actually starts (`ktest.exe`, `xray.exe`, `ciadpi.exe`, `aether.exe`, `psiphon-tunnel-core.exe`, `lyrebird.exe`). Confirm exclusions work on your version before relying on them. Prefer a stable packaged `ktest.exe` path over `go run`, whose temporary executable path changes.

**Note:** Windscribe may change routes or apply its own firewall during connection. If its firewall prevents the bootstrap proxy from being reached, diagnose that specific stage; do not permanently turn off the firewall as a "fix".

## Optional external exit if Windscribe server IPs remain blocked

If you already have a **working local SOCKS5 exit** from Tor, Psiphon, or a user-owned Cloudflare Worker (e.g. the independently deployed `bnkrr/cf-socks` agent), enable it as an additional **late fallback**:

```powershell
.\ktest.exe connect -exit-socks 127.0.0.1:10820
```

The `-exit-socks` argument must point to the already-running local SOCKS5 service, **not** ktest's own 10800/10801 ports. It does not download or deploy a Worker, Tor bridge, or Psiphon itself. The external exit is attempted when ordinary ktest paths fail or take too long (or when learned as the best route), and it is still **TCP-only**. Test the exit on its own first; a listener existing does not prove Internet access. Avoid proxy loops: an external proxy that itself forwards to ktest must not be registered this way.

For the serverless route, see the reference implementation at https://github.com/bnkrr/cf-socks . Running a Worker requires your own Cloudflare account, an authenticated deployment, and a domain/Worker hostname reachable from your network. It is not guaranteed to work on a particular ISP.

## Prove the bootstrap path separately

From a second PowerShell session:

```powershell
curl.exe --max-time 25 -v -x http://127.0.0.1:10801 https://windscribe.com/ -o NUL
```

A completed TLS handshake and an HTTP response from the real site verify a **web path**, not a Windscribe VPN connection. An HTTP 403/404 may be a legitimate server response; distinguish it from a local 502 and TLS or TCP failures.

Next, connect in the Windscribe desktop app, inspect its connection log, and verify that Windscribe itself establishes a tunnel and changes the **external IP**. If API access succeeds but connection fails, check whether the selected Windscribe protocol uses TCP and actually respects the configured upstream proxy.

## Critical boundaries

- **HTTP CONNECT is TCP only.** It cannot transparently carry IKEv2, WireGuard/AmneziaWG, or other UDP protocols. Those need a *real UDP-capable tunnel*, not a webpage/DNS workaround.
- **Opening a Windscribe web page or API alone does not make a blocked server IP reachable.** If Windscribe's tunnel destination is blocked by IP, ktest needs a proven external exit (for example a working Aether/Psiphon/Tor/authorized Worker TCP transport), not a new SNI.
- **ktest's HTTP bridge does not intercept TLS.** ktest's independent, opt-in domain-fronting mode can terminate TLS for selected domains when its CA is installed, but the Windscribe domain family is not included and certificate-pinned clients can reject such interception.
- **Windscribe Proxy Gateway points in the opposite direction.** Do not enable it to supply ktest with an upstream.
- The bridge is available only on localhost and **has no authentication**. Never bind it to your LAN/WAN.
- ktest's ordinary exit methods often keep your real IP, which is acceptable for browsing directly but **does not provide anonymity**. Windscribe becomes the exit only after its own tunnel succeeds.
- If local SOCKS5 can reach an ordinary site but cannot make Windscribe connect, report the stage that failed (Windscribe API, proxy CONNECT, TLS handshake, protocol negotiation, or VPN data plane). Do not declare success solely because HTTP returned 204 or the local port opened.

## What is implemented vs. what still needs network tests

Implemented here: loopback HTTP CONNECT and absolute-form HTTP requests, SOCKS5 forwarding with remote domain names, safe binding, opt-out and port selection, startup integration, local unit tests.

Still requires real-network verification: Windscribe's Windows proxy compatibility for each protocol/version, firewall/split-tunnel interactions, whether an actual Windscribe server address is reachable, and any external exit transport. No real Iranian ISP or Windscribe account was available to these code-level tests.

References: https://windscribe.com/features/proxy-settings and https://windscribe.com/knowledge-base/articles/what-protocols-are-available-with-windscribe .
