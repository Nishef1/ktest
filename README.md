# ktest

A Windows-first toolkit for reaching filtered sites through local anti-DPI methods, optional HTTPS fronting, and verified foreign/Tor exits. Choose a **connection policy**, then choose **coverage**: apps configured to use the local proxy, or Whole PC TCP through a Windows TUN. The Windscribe bridge is separate: Windscribe owns its VPN and exit IP. **Diagnose** reports sampled network behavior rather than promising universal access.

```
go run ./cmd/ktest            # five policies, separate coverage, Diagnose, Setup, CDN and Windscribe tests
go run ./cmd/ktest connect    # connect now
go run ./cmd/ktest doctor     # diagnose, changes nothing
go run ./cmd/ktest windscribe-test -target "Ashburn - Bles Park"  # fixed-entry SNI comparison
go run ./cmd/ktest windscribe-test -verify-vpn                   # one system HTTPS exit-IP check
```

or `.\ktest.exe` from the portable ZIP built by the `windows-portable` workflow.

* Start here: [docs/USAGE.md](docs/USAGE.md)
* **Windscribe mode (`5` or `-mode windscribe`): strict local-only anti-DPI bootstrap.** HTTP proxy `127.0.0.1:10801` uses generated local Xray TCP fragmentation and local ByeDPI strategies. Xray uses only a direct `freedom` outbound with TCP stream slicing; imported subscriptions are never read in this mode. No Psiphon/Aether/WARP/Tor, foreign SOCKS/Worker, plain/direct fallback, unverified Xray profile or CDN takeover can be used. OpenVPN TCP streams are re-wrapped in Windscribe's own WStunnel protocol with chosen SNIs (default `www.speedtest.net,www.digikala.com,www.aparat.com`), and optionally through **your own Cloudflare hostname** (`-windscribe-cdn`) whose origin is a Windscribe WStunnel server. Windscribe itself owns the final public VPN IP and firewall. TCP-only; an established TCP socket does not prove the VPN tunnel is connected. See [docs/WINDSCRIBE_BOOTSTRAP.md](docs/WINDSCRIBE_BOOTSTRAP.md).
* Honest scope: transport, authenticated VPN state and usable data are separate checks. Local test results apply to the sampled entries, names, network and time; unit tests do not establish ISP reachability.
* Nothing is changed outside ktest: no system proxy, DNS, route or firewall. The two optional exceptions are explicit and off by default: the whole-PC tunnel (`connect -tun`, asks for Administrator), and `ktest ca -install`, which trusts a name-constrained local CA so that domain fronting can work.
* Third-party cores (Xray, ByeDPI, sing-box, Wintun) keep their own licenses: [docs/THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md).
