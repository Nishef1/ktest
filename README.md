# ktest

A Windows-first toolkit that tries to reach filtered sites **directly**, without a server of your own and without changing your public IP. One action does it: **Connect** starts every available method at once behind a single local SOCKS5 address and, for each TLS connection, keeps the path that really answers. **Diagnose** tells you what your network does (DNS poisoning, filtered resolvers, whether cutting packets is punished).

```
go run ./cmd/ktest            # menu: Connect / Connect whole PC / Diagnose / Setup / Advanced
go run ./cmd/ktest connect    # connect now
go run ./cmd/ktest doctor     # diagnose, changes nothing
```

or `.\ktest.exe` from the portable ZIP built by the `windows-portable` workflow.

* Start here: [docs/USAGE.md](docs/USAGE.md)
* **Windscribe bootstrap:** Connect now also offers an HTTP proxy on `127.0.0.1:10801`, backed by the same SOCKS5 paths. Set this in Windscribe's **Proxy Settings** (not Proxy Gateway) and try WStunnel/Stealth/TCP. This is TCP-only and does not guarantee Windscribe's tunnel will connect. See [docs/WINDSCRIBE_BOOTSTRAP.md](docs/WINDSCRIBE_BOOTSTRAP.md).
* Honest scope: no result in this repository comes from a measured Iranian ISP. The tool reports what happens on **your** network, right now.
* Nothing is changed outside ktest: no system proxy, DNS, route or firewall. The two optional exceptions are explicit and off by default: the whole-PC tunnel (`connect -tun`, asks for Administrator), and `ktest ca -install`, which trusts a name-constrained local CA so that domain fronting can work.
* Third-party cores (Xray, ByeDPI, sing-box, Wintun) keep their own licenses: [docs/THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md).
