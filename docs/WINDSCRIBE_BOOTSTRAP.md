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

The local HTTP proxy is just a loopback bridge. **HTTP does NOT mean Windscribe's VPN destination port must be 80**. Start with **OpenVPN TCP port 443**. Try WStunnel/443 or Stealth/443 separately if Windscribe's own logs confirm that protocol respects its LAN HTTP proxy. WireGuard/IKEv2 use UDP and cannot travel through this TCP-only HTTP proxy. Do not combine ktest **whole-PC TUN** with Windscribe.

## Allowed versus forbidden in Windscribe mode

**Allowed:** local ByeDPI/ciadpi SOCKS TCP handling and built-in TLS ClientHello packet cutting, which transmit over the user's existing network rather than a foreign exit. ktest may use a trusted encrypted DNS resolver to resolve poisoned domain names. The `127.0.0.1:10800` SOCKS listener remains available; its non-TLS traffic may use only a local ByeDPI path. Windscribe's HTTP CONNECT on `127.0.0.1:10801` only uses local ByeDPI and returns **502** if none is usable.

**Forbidden by code policy:** Aether (any profile), Psiphon (including CDN Fronting), WARP, Tor, remote/externally operated SOCKS5 and Workers, Xray subscription profiles with unknown external outbounds, **plain/no-method** paths, general CDN Fronting/HTTP takeover and the optional whole-PC TUN. A `-exit-socks` argument is rejected. The core router also refuses initial or dynamically added foreign exits and unapproved routes. The Windscribe mode does not prompt to install a MITM certificate.

This conservative design intentionally avoids claiming an unchanged public identity when a third-party CDN relay might change the IP observed by the destination. Anti-DPI packet-shaping itself does not provide an external IP. Consequently it **cannot promise to reach a Windscribe server whose address is blocked independently of SNI/protocol**, and it cannot turn a failed raw OpenVPN TCP tunnel into a successful VPN on its own.

A local SOCKS CONNECT acknowledgement proves TCP establishment, not OpenVPN handshake or sustained VPN data transfer. The final Windscribe state is always owned by Windscribe.

## Monitor and automatic recovery

On Windows, ktest uses the official installed command-line tool:

```powershell
& "C:\Program Files\Windscribe\windscribe-cli.exe" status
```

It polls around every three seconds. If Windscribe reports **Connected** (and no pending tunnel-test marker or network interference), ktest leaves the existing tunnel, country, public IP and firewall under Windscribe control. If ktest starts while Windscribe is already connected, it waits in standby until Windscribe reports a confirmed disconnect. It does not start Aether/Psiphon while waiting.

On a confirmed **Disconnected** state, ktest makes only local anti-DPI paths available. If local ByeDPI is registered and three consecutive checks still say Disconnected, ktest can ask the Windscribe CLI to retry the **last selected location** (not a random country):

```powershell
& "C:\Program Files\Windscribe\windscribe-cli.exe" connect -n
```

The automatic retry interval is at least **three minutes**. ktest never calls `disconnect`, `firewall off`, `ip rotate` or changes locations. It does not reconnect while the CLI says Connecting or Unknown. To disable automatic reconnect without disabling the local HTTP bootstrap or status watcher:

```powershell
go run ./cmd/ktest connect -mode windscribe -windscribe-auto-reconnect=false
```

The first selected local ByeDPI transport is pinned for the Windscribe session to avoid changing it mid-tunnel. A new transport can be considered after Windscribe reports Disconnected.

### Important security / routing limits

- Windscribe's own Firewall (and an appropriate kill-switch policy) is responsible for protecting **other** applications on disconnect. ktest's Windscribe mode is **not** a Windows-wide firewall.
- Windscribe's Firewall **Always On** may prevent any anti-DPI bootstrap while the VPN is disconnected; test this explicitly. Do not silently disable Windscribe Firewall in code.
- If Windscribe routes the ktest/ByeDPI helper's own outbound packets **back through Windscribe**, a routing loop is possible. Use Windscribe **Exclude** split tunneling for a stable compiled `ktest.exe` and `ciadpi.exe` if necessary; `go run` creates temporary executable paths. Verify behavior on your actual Windows build.
- A momentary Windscribe CLI error is not a confirmed disconnect; ambiguity cannot justify leaking sensitive application traffic or toggling other VPNs.
- No real-ISP or installed Windscribe end-to-end test has been performed in CI. Successful Go builds/tests alone do not mean Windscribe's VPN completed authentication and data transfer.

## Troubleshooting

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
- **Windscribe Connected but browsing fails:** consult Windscribe's own logs and firewall/split-tunnel rules; do not launch additional ktest exit paths.

Official source: [Windscribe Desktop CLI](https://github.com/Windscribe/Desktop-App/blob/master/skills/windscribe-cli/SKILL.md).
