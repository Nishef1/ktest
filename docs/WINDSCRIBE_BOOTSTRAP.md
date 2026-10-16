# Windscribe bootstrap: local-only and no extra public-IP exits

The **Windscribe** mode is deliberately different from **Fast**, **Balanced** and **VPN** modes. It helps the **installed Windscribe Windows client** reach its TCP endpoint using local packet-level anti-DPI methods. **ktest must never launch Psiphon, Aether, WARP, Tor or an external SOCKS/Worker exit in Windscribe mode**, even when those cores are installed or enabled under Setup. ktest does not select or change a public VPN egress IP: **only Windscribe itself can do so after its own tunnel connects**.

## Run

```powershell
cd D:\Data\ktest
git pull --ff-only origin main
go run ./cmd/ktest connect -mode windscribe -v
```

Menu option **8** launches the same mode. Windscribe **Proxy Settings** (not Proxy Gateway):

| Setting | Value |
| --- | --- |
| Type | HTTP |
| Address | `127.0.0.1` |
| Port | `10801` |
| Username/password | leave empty |

The local HTTP proxy is just a loopback bridge. **HTTP does NOT mean Windscribe's VPN destination port must be 80**. Start with **OpenVPN TCP port 443**. The supplied Windscribe 2.25.4 Windows logs explicitly ignore the LAN proxy for WireGuard, IKEv2, Stealth and WStunnel. Use OpenVPN TCP to test this bootstrap; a connection through those other protocols does not verify ktest's VPN transport. ktest reports the selected protocol when it observes a connecting/connected non-TCP tunnel. Do not combine ktest **whole-PC TUN** with Windscribe.

## WStunnel bridge: chosen SNI, optional own CDN

Set Windscribe to **OpenVPN TCP** (port 443) with the HTTP proxy above. Windscribe then sends `CONNECT <OpenVPN TCP IP>:443` to ktest. ktest waits for the first bytes: TLS/HTTP (Windscribe API) uses the existing SOCKS response selector across permitted local anti-DPI paths; anything else is OpenVPN and is re-wrapped exactly like Windscribe's own **WStunnel** protocol ([source](https://github.com/Windscribe/wstunnel)): TLS, then a WebSocket upgrade to `/tcp/127.0.0.1/1194`, then binary messages. The Windscribe node forwards that to its own OpenVPN server, so credentials, encryption and the public exit stay Windscribe's. Differences from the official client: a Chrome-like TLS ClientHello offering only `http/1.1`, and a **chosen SNI**.

### How a carrier is chosen (Shir-o-Khorshid style, Windscribe instead of Psiphon)

Shir-o-Khorshid, Se7en Pro and MahsaNG all run Psiphon: they scan CDN IPs and reach **Psiphon's own meek servers** that Psiphon keeps behind Cloudflare/Akamai/Fastly (`FrontedMeekCDNScan` / `FrontedMeekDialOverride` in psiphon-tunnel-core). Windscribe keeps no VPN server behind any CDN (its Cloudflare hostnames are only the website and API; checked 2026-10-16), so the CDN scan alone cannot reach it. What ktest copies is the method: many candidates, tested on your network, the first that really answers wins.

For each new OpenVPN connection ktest sends the client stream over **every** carrier, launched 250 ms apart, and keeps the first one that **returns a complete TCP-framed OpenVPN server control packet**. It checks the length and server opcode, buffering fragmented replies until the first packet is complete. HTTP error pages, client-only/data opcodes and truncated packets cannot win. This is a framing check, not authentication. Windscribe's **Protocol Tweaks / J - Iran Junk Packets** can stay enabled: junk and subsequent handshake bytes are forwarded in order while the race runs, and a carrier that opens later receives the entire buffered prefix before new bytes. A silent or blocked carrier does not stall the others. The losers are closed and new client data continues only on the winner. Windscribe itself authenticates the OpenVPN response and completes login; ktest does not check tls-auth or claim that the VPN is connected merely because a correctly shaped packet arrived.

The race lasts at most 25 seconds and retains at most 1 MiB before any carrier answers. Exceeding that pre-answer limit fails the connection rather than dropping bytes. After selection, sent bytes are released and normal flow control bounds the pending buffer, so the limit does not cap VPN data transfer. Closing the client cancels pending carrier dials and blocked writes. Internal Xray/ByeDPI carrier attempts remain available in verbose diagnostics but do not produce separate site-feed events; ordinary Windscribe API connections still do.

| Carrier | Where it goes | TLS SNI |
| --- | --- | --- |
| `CDN host@edge` (only with `-windscribe-cdn`) | your Cloudflare hostname → its origin, a Windscribe WStunnel IP | your hostname (or `-windscribe-cdn-sni`), certificate verified |
| `WStunnel sni=… @IP` | alternate addresses advertised for this exact node, WebSocket `/tcp/127.0.0.1/1194` | each of `-windscribe-wstunnel-sni` |
| `Stealth sni=… @IP` | the same advertised candidates, TLS then raw OpenVPN | each of `-windscribe-wstunnel-sni` |
| `raw OpenVPN +anti-DPI` | the OpenVPN TCP IP itself through local Xray/ByeDPI | none (not TLS) |

Every TLS carrier runs twice: straight, and with its TCP leg through local Xray/ByeDPI (`+anti-DPI`). Direct WStunnel carriers reject certificates without a Windscribe hostname; this name check alone does not authenticate ownership. Stealth endpoints can present a generic certificate without that name, so only provider-advertised Stealth addresses are eligible and the outer TLS name is not checked, matching [Windscribe's own wrapper](https://github.com/Windscribe/wstunnel/blob/main/cli/httpClient.go). The inner OpenVPN client authenticates its server in either case. CDN carriers retain normal TLS chain and hostname verification. Default SNIs: `www.speedtest.net,www.digikala.com,www.aparat.com`. A carrier whose stream stayed up ≥1 min with ≥64 KiB received is launched first next time; one whose stream died within 20 s is launched last for ten minutes. `-windscribe-wstunnel=false` disables WStunnel and Stealth. The live feed prints `Windscribe carrier returned data via …; VPN not yet verified`.

ktest downloads Windscribe's public `openvpn` node lists over verified HTTPS through the permitted API selector: the global list (`country_override=ZZ`) and the regional list. It matches the client's CONNECT IP to the exact node's `ip2` and tests that node's advertised `ip` and `ip3`, deduplicated across both lists. Regional anti-censorship addresses can be completely unrelated numerically to `ip2`; ktest never computes adjacent IPs or switches to another location. The official desktop client uses an account-provided [PortMap](https://github.com/Windscribe/Desktop-App/blob/master/src/client/client-common/api_responses/portmap.cpp) to choose an address field per protocol. This bridge does not fetch account credentials or that authenticated map, so it tries both alternate fields on port 443 rather than assuming either is universally WStunnel or Stealth. An address accepting TLS alone does not prove that protocol works there.

The validated public lists are cached in `<base>/cache/windscribe-nodes.json` for up to 24 hours and refreshed at startup and every 30 minutes. Failed downloads retry after 30 seconds, so a startup failure does not disable discovery for half an hour. Downloads are capped at 4 MiB per list, take at most ten seconds each, and do not follow redirects. An unavailable or invalid update preserves the previous fresh snapshot. Conflicting node identities are not mixed. Without a fresh exact-node mapping, the original raw OpenVPN destination remains available; `-windscribe-wstunnel-ip` explicitly overrides only the WStunnel address. A first request can wait up to three seconds for the initial list download before starting its 25-second race. A regional list fetched through an existing VPN reflects that VPN's region, so it cannot establish which alternatives the ISP would receive while disconnected.

With `-v`, each failed carrier includes its actual destination, list source and failure stage: `tcp`, `tls`, `websocket`, or `openvpn` (waiting for a complete server control packet). If all carriers fail, the feed shows one summary such as `Windscribe race failed [tcp=2, tls=3, websocket=1, openvpn=4]`. These identify the failing boundary; the OpenVPN framing check does not validate authentication.

In the Paris regression, probing a supposed Stealth carrier on an advertised WStunnel address returned `HTTP/1.1 501 Not Implemented` from nghttpx. Selecting any nonempty reply let that HTTP page win; Windscribe then logged `Bad encapsulated packet length ... (18516)`, the big-endian value of the `HT` prefix. A fast HTTP error now fails that carrier and leaves the other attempts running. Tests cover fragmented replies, incomplete packets, and preserving the winner's full first packet.

A 2026-10-16 transport preflight through an already connected Ashburn VPN obtained HTTP 101 from the advertised `ip` addresses of Atlanta, Sweden and New Jersey. The same nodes' `ip3` addresses failed the earlier Windscribe certificate-name check. A subsequent Paris investigation found that this check incorrectly excluded generic certificates used by Stealth; that rejection was not evidence of an unrelated server. Addresses still come from the provider rather than IP arithmetic. Transport preflights alone do not establish connectivity from the ISP or complete a new VPN login.

Measured on 2026-10-16 on the author's ISP with Windscribe disconnected: Windscribe's own WStunnel client failed against `68.67.118.162` (timeout / `tls: illegal parameter`), while this bridge with SNI `www.speedtest.net` got HTTP 101 from `68.67.118.162` and `198.44.157.27`, and a tls-auth-signed OpenVPN `P_CONTROL_HARD_RESET_CLIENT_V2` sent through it was answered with `P_CONTROL_HARD_RESET_SERVER_V2` by both. A later installed-Windows test with Windscribe 2.25.4 reached `Logged in`, `Connected` and `TCP:443` through `WStunnel sni=www.speedtest.net` with **J - Iran Junk Packets enabled**, after fixing API response selection and applying the loopback routing setting below. This is evidence for that tested location/network, not every carrier or ISP.

### Optional: your own Cloudflare hostname

ktest cannot create this for you; it needs your Cloudflare account and a domain on it.

1. Pick one Windscribe location and its working WStunnel IP (Windscribe log line `Connecting to IP: "…" protocol: "WStunnel"`, or an advertised address whose WebSocket upgrade succeeds in verbose diagnostics).
2. In Cloudflare DNS add an `A` record, e.g. `ws.example.com` → that IP, **Proxied** (orange cloud).
3. SSL/TLS mode **Full** (not *Full (strict)*: the origin presents a `windscribe.com` certificate). WebSockets stay on (default).
4. Run ktest. Without `-windscribe-cdn-edge` it scans up to 300 official Cloudflare IPs for edges this network reaches **and** that carry your hostname to a WebSocket upgrade (HTTP 101), and keeps the six fastest, like Shir-o-Khorshid's IP scan.

```powershell
go run ./cmd/ktest connect -mode windscribe -windscribe-cdn ws.example.com -v
```

Every OpenVPN connection then reaches that **one** origin, whatever location Windscribe shows; keep Windscribe on the same location to avoid confusion. Cloudflare sees only TLS-wrapped OpenVPN between you and Windscribe; it is a transport hop, not an exit. Check Cloudflare's terms for your plan before relying on it.

## Allowed versus forbidden in Windscribe mode

**Allowed:** the WStunnel bridge above (direct to a certificate-checked Windscribe node, or through the CDN hostname you configured), generated local Xray TCP fragmentation, local ByeDPI/ciadpi SOCKS TCP handling, and built-in TLS ClientHello packet cutting. These transmit over the user's existing network rather than a foreign exit. ktest may use a trusted encrypted DNS resolver to resolve poisoned domain names. The `127.0.0.1:10800` SOCKS listener remains available; its non-TLS traffic may use only explicitly managed local TCP methods. Windscribe's HTTP CONNECT on `127.0.0.1:10801` rotates through local Xray/ByeDPI methods and returns **502** if no eligible local core accepts the request.

Xray in this mode uses **only ktest-generated configuration**, with one loopback TCP SOCKS inbound and one `freedom` outbound whose `fragment.packets` is a numeric TCP-write range. It never reads `Serverless-for-Iran.json`, accepts a redirect, or chains another proxy. This differs from `tlshello` fragmentation: raw OpenVPN TCP frames are not TLS ClientHello records. Two local variants provide different fragment lengths/timing; they are candidates, not measured ISP successes. `-no-xray` disables both. See [Xray Freedom fragmentation](https://xtls.github.io/en/config/outbounds/freedom.html#fragmentobject).

**Forbidden by code policy:** Aether (any profile), Psiphon (including CDN Fronting), WARP, Tor, remote/externally operated SOCKS5 and Workers, Xray subscription profiles with unknown external outbounds, **plain/no-method** paths, general CDN Fronting/HTTP takeover (the only CDN use is the WStunnel carrier to your own hostname) and the optional whole-PC TUN. A `-exit-socks` argument is rejected. The core router also refuses initial or dynamically added foreign exits and unapproved routes. The Windscribe mode does not prompt to install a MITM certificate.

This conservative design intentionally avoids claiming an unchanged public identity when a third-party CDN relay might change the IP observed by the destination. Anti-DPI packet-shaping itself does not provide an external IP. Consequently it **cannot promise to reach a Windscribe server whose address is blocked independently of SNI/protocol**, and it cannot turn a failed raw OpenVPN TCP tunnel into a successful VPN on its own.

Windscribe API TLS requests use the same first-response selection as the SOCKS listener, including permitted built-in ClientHello methods. This avoids pinning API/login traffic to an Xray/ByeDPI method that accepts TCP but never returns TLS. Opaque carrier TCP legs still use the strict local-core dialer.

A local SOCKS CONNECT acknowledgement proves that the local core accepted the request; some cores acknowledge before dialing the destination. It does not prove destination TCP establishment, OpenVPN handshake or sustained VPN data transfer. The final Windscribe state is always owned by Windscribe.

## Monitor and automatic recovery

On Windows, ktest uses the official installed command-line tool:

```powershell
& "C:\Program Files\Windscribe\windscribe-cli.exe" status
```

It polls around every three seconds. If Windscribe reports **Connected** (and no pending tunnel-test marker or network interference), ktest leaves the existing tunnel, country, public IP and firewall under Windscribe control. If ktest starts while Windscribe is already connected, it waits in standby until Windscribe reports a confirmed disconnect. It does not start Aether/Psiphon while waiting.

On a confirmed **Disconnected** state, ktest makes only local anti-DPI paths available. If a local Xray/ByeDPI method is registered and three consecutive checks still say Disconnected, ktest can ask the Windscribe CLI to retry the **last selected location** (not a random country):

```powershell
& "C:\Program Files\Windscribe\windscribe-cli.exe" connect -n
```

The automatic retry interval is at least **three minutes**. ktest never calls `disconnect`, `firewall off`, `ip rotate` or changes locations. It does not reconnect while the CLI says Connecting or Unknown. To disable automatic reconnect without disabling the local HTTP bootstrap or status watcher:

```powershell
go run ./cmd/ktest connect -mode windscribe -windscribe-auto-reconnect=false
```

Each **new HTTP CONNECT** rotates to the next eligible local Xray/ByeDPI method for that exact **host:port**, in stable configured rank/order. If TCP/SOCKS establishment fails, the remaining local methods are tried within the same request; if all fail, the proxy returns 502. If TCP establishment succeeds but the VPN later resets or stalls, Windscribe's next connection to that destination tries the next method. Retry history expires after the configured memory TTL (30 minutes by default).

API/DNS requests and other destinations have independent retry histories. TCP acceptance never pins the whole Windscribe session or trains the verified-answer scores. Existing streams keep their original transport; ktest neither replays opaque VPN bytes nor migrates live connections. The proxy does not interpret VPN authentication or infer VPN success from server bytes. Windscribe still owns handshake validation and decides when to reconnect.

The live feed labels these events **TCP proxy accepted; VPN handshake not verified**, without a green success mark or inclusion in the answered-connection count. `11 of 11 ready` only means eleven local processes/listeners started, not that eleven methods passed a VPN handshake.

### Important security / routing limits

- Windscribe's own Firewall (and an appropriate kill-switch policy) is responsible for protecting **other** applications on disconnect. ktest's Windscribe mode is **not** a Windows-wide firewall.
- Windscribe's Firewall **Always On** may prevent any anti-DPI bootstrap while the VPN is disconnected; test this explicitly. Do not silently disable Windscribe Firewall in code.
- If Windscribe routes the ktest/ByeDPI/Xray helpers' own outbound packets **back through Windscribe**, a routing loop is possible. Use Windscribe **Exclude** split tunneling for a stable compiled `ktest.exe`, `ciadpi.exe` and `xray.exe` if necessary; `go run` creates temporary executable paths. Verify behavior on your actual Windows build.
- A momentary Windscribe CLI error is not a confirmed disconnect; ambiguity cannot justify leaking sensitive application traffic or toggling other VPNs.
- No real-ISP or installed Windscribe end-to-end test has been performed in CI. Successful Go builds/tests alone do not mean Windscribe's VPN completed authentication and data transfer.

## Troubleshooting

### Windows loopback proxy: `CONNECTED,ROUTE_ERROR`

If OpenVPN logs `Initialization Sequence Completed` but its management state is `CONNECTED,ROUTE_ERROR`, inspect the preceding route commands. In the live Windows test, OpenVPN attempted `route ADD 127.0.0.1 MASK 255.255.255.255 0.0.0.0 IF 1` and reported that gateway `0.0.0.0` was unreachable. Windscribe stayed Connecting and retried despite successful authentication and momentary data transfer. Its [OpenVPN connector](https://github.com/Windscribe/Desktop-App/blob/master/src/client/engine/engine/connectionmanager/connectors/openvpn/openvpnconnection.cpp) recognizes `CONNECTED,SUCCESS` as a completed connection.

For this loopback-proxy failure, add this line to Windscribe's **Advanced Parameters**, preserving existing entries:

```text
redirect-gateway def1 autolocal
```

OpenVPN's documented [`autolocal` flag](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html) detects a local transport endpoint and skips the unnecessary remote-host exception route. The installed test then logged `ROUTE remote_host is LOCAL` and `CONNECTED,SUCCESS`. Windscribe stores Advanced Parameters in `%LOCALAPPDATA%\Windscribe\Windscribe2\windscribe_extra.conf`; it may need to be restarted to apply them. ktest does not automatically edit that file or change system routes. To undo the setting, remove only that line from Advanced Parameters.

### Other checks

```powershell
go run ./cmd/ktest connect -mode windscribe -v
```

On a separate terminal:

```powershell
& "C:\Program Files\Windscribe\windscribe-cli.exe" status
curl.exe -v -x http://127.0.0.1:10801 https://www.cloudflare.com/cdn-cgi/trace --max-time 15
```

- **502 from localhost:** no eligible local anti-DPI path could establish the TCP destination; this is an expected honest failure, not a reason to run Psiphon.
- **HTTP CONNECT 200 then Windscribe WAIT/reset:** only TCP was accepted; the Windscribe handshake still failed. Distinguish server-IP blocking, TLS/protocol fingerprints and other network interference from a mere proxy handshake.
- **Only the normally reachable country connects:** check `windscribe-cli status` for the protocol. WireGuard (including Windscribe's own AmneziaWG tweaks) bypasses this HTTP VPN transport. Compare the same failing location using OpenVPN TCP/443; new attempts rotate local methods, but local packet manipulation cannot guarantee access to an IP/protocol blocked by the network.
- **Windscribe Connected but browsing fails:** consult Windscribe's own logs and firewall/split-tunnel rules; do not launch additional ktest exit paths.

Official source: [Windscribe Desktop CLI](https://github.com/Windscribe/Desktop-App/blob/master/skills/windscribe-cli/SKILL.md).
