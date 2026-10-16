# Windscribe bootstrap with ktest

The goal is **not** to replace Windscribe. It is to give the installed Windscribe desktop client an initial TCP path through ktest's existing censorship-circumvention methods. Once Windscribe establishes its own tunnel, Windscribe is the primary VPN and supplies the external IP.

## Automatic Windscribe watchdog and recovery (Windows)

`ktest connect -mode windscribe` now uses Windscribe's **own official command-line tool** to determine VPN state:

```powershell
& "C:\\Program Files\\Windscribe\\windscribe-cli.exe" status
```

The desktop CLI reports connection status, firewall and protocol through the Windscribe service. ktest reads the CLI every ~3 seconds; it does **not** infer that the VPN is connected from a local port, adapter, or a page returning HTTP 200.

- **Confirmed Connected:** Windscribe owns the default route, public exit IP and firewall. If ktest was just launched while connected, it stays in standby and does not start its bootstrap cores. If Windscribe connects while ktest is already providing a TCP proxy, ktest **keeps the established proxy transport alive** (otherwise that action could disconnect Windscribe), but stops launching new Aether discovery attempts.
- **Confirmed Disconnected:** ktest activates/resumes external exit discovery. Once a verified foreign TCP exit is ready, it asks Windscribe to retry the **last selected location** with `windscribe-cli connect -n`. Retries are limited to once every 60 seconds to avoid connection loops.
- **Connecting / tunnel test pending / network interference:** ktest does not issue duplicate connection requests. A `*Connected` status is **not** treated as a completed tunnel.
- **CLI unavailable / ambiguous:** no automatic reconnect is attempted. If monitoring has not started, ktest continues in manual-bootstrap mode with an explicit warning.

**No automatic country changes, IP rotations, VPN disconnections, Windscribe firewall changes, or ktest system-wide TUN changes are performed.** The watchdog is a helper, not a replacement for Windscribe's OS-level firewall. It cannot guarantee that arbitrary applications won't leak traffic during a disconnect if Windscribe's firewall is off.

To disable automatic CLI reconnect while still using the HTTP bootstrap:

```powershell
go run ./cmd/ktest connect -mode windscribe -windscribe-auto-reconnect=false -v
```

If installed in a nonstandard directory:

```powershell
go run ./cmd/ktest connect -mode windscribe -windscribe-cli "D:\\Apps\\Windscribe\\windscribe-cli.exe"
```

**IMPORTANT route-loop boundary:** Windscribe's OpenVPN-over-HTTP session may depend on an already running Aether/Psiphon exit *for its entire lifetime*. Do not kill that exit the moment Windscribe connects. Exclude the stable ktest/Aether binaries from Windscribe's VPN tunnel if necessary and verify they use the physical network; otherwise the VPN can become its own upstream. Windscribe also has an option to force-close TCP sockets on connect, which may terminate existing bootstrap connections. Test this with real Windows logs before promising automatic recovery.

**Firewall:** For sensitive workloads, configure Windscribe's own firewall policy; `ktest` neither weakens nor disables it. Always On may prevent external bootstrap traffic during a disconnected state, so successful recovery in that mode must be validated experimentally rather than assumed.

## 2026-10-16: Why HTTP CONNECT 200 did not connect the VPN

The OpenVPN/TCP logs for Istanbul (ports 443 and 80), another Istanbul server, and Berlin (443 and 8080) all reach `HTTP/1.1 200 Connection Established`, then remain in `WAIT` and reset. The log also shows that ordinary WireGuard ignores LAN HTTP Proxy, so those WireGuard attempts did not test the proxy at all.

**Root cause in ktest:** the previous SOCKS proxy returned CONNECT success before choosing a real outbound. For opaque, non-TLS OpenVPN traffic its plain/direct path could open a TCP socket to a filtered VPN address, return HTTP 200, then never receive a valid server handshake. A working web front for YouTube does not provide a TCP relay to arbitrary VPN server addresses. When Psiphon and WARP fail to start, there is no verified foreign egress to carry that server-side OpenVPN TCP stream.

**Fix on main:** in `-mode windscribe` only, the HTTP listener `127.0.0.1:10801` now uses a strict verified-exit dialer. If no verified, non-Iran/non-Russia foreign SOCKS egress is ready, it returns `HTTP 502` instead of `200`. If a verified exit connects to the requested remote IP:port, `200` is returned. The first verified exit is pinned per ktest session. This only verifies a TCP tunnel, not OpenVPN authentication or VPN data flow.

**Actionable test:**

1. Leave ktest running in Windscribe mode, and keep its whole-PC TUN disabled.
2. First inspect the ktest terminal: wait for a message confirming a *verified foreign exit*, e.g. Psiphon. `Exit: searching` does not count.
3. While no exit has come up, a Windscribe OpenVPN/TCP CONNECT should fail with 502 instead of displaying a misleading success. This is expected. If it does not, capture the current WinDscribe and `ktest -v` logs.
4. When an actual verified exit appears, select **OpenVPN TCP, 443**, then retry. Test `WStunnel, 443` independently, but do not assume Windscribe's LAN-proxy setting is honored for every protocol without confirming it in the logs.
5. DNS-over-8.8.8.8 is blocked on this ISP. Windscribe's DNS policy is set to Google; after the TCP path actually works, inspect whether DNS within Windscribe still needs adjustment. The October 16 TCP logs already show IP literals and therefore do not identify DNS poisoning as the immediate OpenVPN handshake failure.
6. Check the Windscribe firewall settings, especially Manual, Automatic and Always On. Keep the desired leak protection; changing it must not be presented as a permanent fix for blocked VPN servers.

The `tried=0, actual=88` warning occurs after OpenVPN has started writing. Its meaning must not be inferred as a `ktest` HTTP-proxy bug based only on that log line; TCP reset and absence of remote OpenVPN response are the primary observations.

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
