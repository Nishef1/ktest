# Windscribe mode: local anti-DPI only (no foreign proxy exits)

**Security rule (strict):** `ktest connect -mode windscribe` MUST NOT start or route through Psiphon, Aether, WARP, Tor, external SOCKS5 relays, subscription Xray profiles with unknown outbounds, or any other foreign-IP-changing tunnel. It also forbids `-exit-socks`, plain/direct fallbacks for its Windscribe HTTP CONNECT, full-PC TUN, and CDN fronting takeovers. None of these prohibitions can be overridden using the usual Connect settings. Other connection modes retain their own policies.

This mode uses only locally launched ByeDPI/ciadpi anti-DPI SOCKS cores, which attempt to connect to the **original Windscribe server** over the user's ISP. Splitting/faking packets or altering their timing does not create a foreign VPN egress. The client retains its own public IP **until Windscribe itself connects**, at which point Windscribe manages the full-system VPN and resulting public IP. A local anti-DPI method cannot necessarily solve server IP-level blocking; failure must be reported rather than falling back to Psiphon.

## Windows setup

```powershell
git pull --ff-only origin main
go run ./cmd/ktest connect -mode windscribe -v
```

In the Windscribe desktop app, open **Preferences → Connection → Proxy Settings**. Select HTTP, address `127.0.0.1`, port `10801`, with blank username/password. This is Windscribe's *upstream LAN proxy*, **not** Proxy Gateway. Test **OpenVPN TCP/443** first; test Stealth or WStunnel/443 separately only if logs confirm that the installed Windscribe version actually honors the HTTP proxy for that protocol. WireGuard/IKEv2 use UDP and do **not** pass through this HTTP proxy. HTTP proxy port 10801 does NOT mean the actual Windscribe server port must be 80.

Only the local HTTP CONNECT listener supplies a Windscribe bootstrap connection. A `HTTP/1.1 200 Connection Established` means a local anti-DPI core acknowledged the TCP CONNECT to a server; it does **not** prove that OpenVPN authenticated, responded or delivered VPN packets. A `502` means no permitted local anti-DPI TCP route was available. An external tunnel is never used as a fallback.

**Do not combine Windscribe mode with `ktest -tun` or an old active `sing-tun` adapter.** If ktest is started with Windscribe already connected, it stands by for the CLI to report a true disconnection. Normal applications should use Windscribe's tunnel and firewall, not ktest's SOCKS proxy when the VPN is connected.

## Official Windscribe CLI watchdog

`ktest` uses Windscribe's own `windscribe-cli status` on Windows, typically found at:

```powershell
& "C:\Program Files\Windscribe\windscribe-cli.exe" status
```

The CLI is the authority for Connected, Disconnected, Connecting and pending tests (marked `*Connected`). An unknown/temporarily failing CLI does not trigger a speculative reconnection.

- **Connected:** Windscribe controls its tunnel, selected server, external IP, default route and firewall. ktest does not launch any foreign exit. Already established local ByeDPI sockets must remain available if Windscribe's own TCP upstream depends on them.
- **Disconnected:** ktest keeps its local ByeDPI bypass available, and may ask the official Windscribe CLI to reconnect the **last location** via `windscribe-cli connect -n`, only after several confirmed disconnected samples. Reconnect attempts are rate-limited (at least three minutes apart).
- **Connecting / pending / unknown:** no duplicate reconnect action is taken.

To turn off CLI auto-reconnect (without disabling manual Windscribe startup):

```powershell
go run ./cmd/ktest connect -mode windscribe -windscribe-auto-reconnect=false -v
```

If the CLI is installed elsewhere, use `-windscribe-cli "C:\absolute\path\windscribe-cli.exe"`.

ktest does **not** change the selected country, rotate Windscribe IPs, disable its firewall, log into the user's account, or capture the whole Windows network. Windscribe's own Firewall must be configured for the user's safety requirements; ktest's proxy is not a persistent system-wide kill switch. An Always On firewall could also prevent the initial anti-DPI bootstrap from reaching the physical network, so test the actual firewall behavior instead of permanently disabling it.

## Troubleshooting the logged failure

The recorded Windscribe attempts on several countries/ports previously returned `HTTP CONNECT 200`, then stalled in OpenVPN `WAIT` and reset. Earlier builds sometimes gave a false HTTP 200 after opening a raw filtered TCP socket, or redirected the connection through a foreign Psiphon IP. Both behaviors violate the current Windscribe policy and are removed. On this network Google/YouTube fronting success says nothing about carrying an arbitrary raw OpenVPN stream to a Windscribe IP.

New logs should be checked in order: whether a permitted **local ByeDPI** SOCKS listener starts; whether its TCP CONNECT to the actual Windscribe IP:port succeeds; whether the remote server sends VPN negotiation bytes; and whether Windscribe CLI reaches real `Connected`. If TCP succeeds but the VPN times out, local fragmentation alone might not bypass the blocking; **do not silently switch to a foreign proxy**.

## Scope and verification

This is a code-level policy and loopback TCP integration. CI can prove the forbidden paths do not register, the bridge cannot pick foreign exits, and builds are healthy. CI cannot prove that a particular ISP permits Windscribe OpenVPN traffic, that the external IP stays constant across VPN reconnects, or that every Windscribe protocol obeys Proxy Settings. For a truly stable exit IP, select a consistent Windscribe endpoint, or its separately offered Static IP feature.

Reference: [Windscribe Desktop-App official CLI documentation](https://github.com/Windscribe/Desktop-App/blob/master/skills/windscribe-cli/SKILL.md).
