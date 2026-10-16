# ktest

A Windows-first toolkit that tries to reach filtered sites **directly**, without a server of your own and without changing your public IP. One action does it: **Connect** starts every available method at once behind a single local SOCKS5 address and, for each TLS connection, keeps the path that really answers. **Diagnose** tells you what your network does (DNS poisoning, filtered resolvers, whether cutting packets is punished).

```
go run ./cmd/ktest            # menu: Connect / Connect whole PC / Diagnose / Setup / Advanced
go run ./cmd/ktest connect    # connect now
go run ./cmd/ktest doctor     # diagnose, changes nothing
```

or `.\ktest.exe` from the portable ZIP built by the `windows-portable` workflow.

* Start here: [docs/USAGE.md](docs/USAGE.md)
* **Windscribe mode (`8` or `-mode windscribe`): strict local-only anti-DPI bootstrap.** HTTP proxy `127.0.0.1:10801` uses generated local Xray TCP fragmentation and local ByeDPI strategies. Xray uses only a direct `freedom` outbound with TCP stream slicing; imported subscriptions are never read in this mode. No Psiphon/Aether/WARP/Tor, foreign SOCKS/Worker, plain/direct fallback, unverified Xray profile or CDN takeover can be used. Windscribe itself owns the final public VPN IP and firewall. TCP-only; an established TCP socket does not prove the VPN tunnel is connected. See [docs/WINDSCRIBE_BOOTSTRAP.md](docs/WINDSCRIBE_BOOTSTRAP.md).
* Honest scope: no result in this repository comes from a measured Iranian ISP. The tool reports what happens on **your** network, right now.
* Nothing is changed outside ktest: no system proxy, DNS, route or firewall. The two optional exceptions are explicit and off by default: the whole-PC tunnel (`connect -tun`, asks for Administrator), and `ktest ca -install`, which trusts a name-constrained local CA so that domain fronting can work.
* Third-party cores (Xray, ByeDPI, sing-box, Wintun) keep their own licenses: [docs/THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md).
