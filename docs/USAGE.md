# Using ktest

The everyday path needs no options and no knowledge of the methods behind it.

```
.\ktest.exe                 menu: Connect, Connect whole PC, Diagnose, Setup, Advanced
.\ktest.exe connect         connect now
.\ktest.exe connect -cert   set up or renew the fronting certificate, then connect
.\ktest.exe connect -tun    the same for every application on the PC (asks for Administrator)
.\ktest.exe doctor          diagnose; changes nothing
```

From source: `go run ./cmd/ktest` (see "Where ktest looks for its files").

## 1. Connect

Connect starts every available method at once and puts **one** local SOCKS5 address in front of them: `socks5://127.0.0.1:10800`. Point an application at it and turn on "proxy DNS" / remote DNS (in Firefox: Settings → Network Settings → Manual proxy → SOCKS Host `127.0.0.1`, Port `10800`, SOCKS v5, and tick "Proxy DNS when using SOCKS v5").

The screen shows four phases with a percentage and a final state:

| Phase | What happens |
| --- | --- |
| Checking the network | System DNS is asked for `www.youtube.com`; a private answer such as `10.10.34.x` is reported as **poisoned**. The public resolver 8.8.8.8 is probed with a real query. |
| Starting external paths | Xray fragment A and B and the ByeDPI strategies from `profiles/byedpi-strategies.txt` start side by side. A bar shows how many are ready; a core that cannot start is listed with its reason. |
| Verifying YouTube and Google | Both are fetched through the proxy and directly, with certificate-verified HTTPS. |
| Result box | **READY** (all reachable), **PARTLY READY** (some), **NOT VERIFIED** (none). It also says whether a site was blocked directly and open through ktest (*bypass confirmed*) or open both ways (nothing to bypass; if another VPN is on, turn it off to see a bypass). |

After the box, a live list shows each site once, with the path that won (`youtube.com ← ByeDPI fake packet, low TTL 0.6s`), and a site that no path could reach. Enter or Ctrl+C disconnects and prints a session summary: the share of connections that were answered and which paths won how often.

Nothing outside ktest is changed: no system proxy, DNS, route, firewall or certificate. On Windows ktest runs inside a kill-on-close job object, so closing the window or killing ktest also ends every core and frees the ports.

## 2. How the methods are chosen

There is no manual choice to make. Censorship differs per site and per network, and a method that works today may not tomorrow, so ktest races:

* **Paths.** `plain` (the untouched connection, always present because some networks punish any cut ClientHello even for unblocked sites), `plain6` (the same over IPv6), the Xray profiles, the ByeDPI strategies (adaptive, fake packets, low TTL, split + disorder, out-of-band, TLS record slicing), and three built-in families that cut the ClientHello inside the SNI over TCP segments and/or TLS records, with random cut points and pauses per connection (plus IPv6 twins).
* **Two waves.** For each TLS connection the first wave is one path: the one remembered for that site, otherwise the best ranked. If it has not produced a TLS record after 250 ms (1 s for a remembered path) or fails, **every other path starts at once**. The first path that returns a TLS handshake record wins. Nothing has reached the application before that, so a failed attempt is replayed on another path without the application noticing. TLS stays end to end; the application verifies the certificate.
* **Ranking.** A path is ranked by its smoothed success rate, then by how intrusive it is (plain, then external cores, then built-in cuts), then by latency. Win counts alone are not used, because they let whichever path won first keep winning.
* **Memory.** The winner is remembered per site (`r1---sn-x.googlevideo.com` and `i.ytimg.com` share nothing, but every `googlevideo.com` node shares one entry) for 30 minutes, in memory only. Nothing about visited sites is written to disk.

## 3. Names (DNS)

Name resolution is the first thing a censor poisons, so it is not left to the system resolver alone:

1. The system answer is used when it is a real address. Private or reserved addresses are treated as poisoning and never dialed.
2. Otherwise encrypted DNS is asked by IP literal (so no DNS is needed to find the resolver): Cloudflare `104.16.248.249`, `104.16.249.249`, `1.1.1.1` and Google `8.8.8.8`, `8.8.4.4`. All are tried at once, through every working path and the direct route, and the first answer wins. After three failures in a row encrypted DNS is skipped for five minutes, because it is itself filtered on many networks. Cloudflare's 1.1.1.1 and 1.0.0.1 are also asked under a decoy server name (`www.microsoft.com`), as the MITM-DomainFronting project does; the certificate is still verified for Cloudflare's real names.
3. The Xray paths receive the trusted address too (they would otherwise need their own DNS, which is filtered the same way); if no trusted address exists they fall back to the name and use their own DNS.
4. For Google-owned names (youtube.com, ytimg.com, googlevideo.com, gstatic.com, ...) the address of `www.google.com` stands in, since Google front ends serve them; a path that cannot is simply a lost race.

## 4. Diagnose

`Diagnose` (or `ktest doctor`) checks the package, local ports and the network without starting anything, then measures:

* what the system resolver answers (and flags poisoning),
* whether each encrypted-DNS address completes a TLS handshake,
* a table of certificate-verified handshakes to a Google front end for an unblocked name (`www.google.com`) and a blocked one (`www.youtube.com`), each with the untouched ClientHello and each built-in cutting shape,
* a **verdict**. The important one: if the blocked name fails and every cut ClientHello also fails for the unblocked name, the network punishes cutting, so Xray fragment, ByeDPI split/slice and the built-in cuts cannot help; only methods that do not cut (fake packets with a low TTL, IPv6, QUIC) remain.

Run it once with any other VPN off and keep the output with your notes: it is the evidence for choosing methods.

## 5. Domain fronting (optional)

Cutting the ClientHello can only hide the server name by splitting it; some networks punish any cut (field reports say fragmentation is closed on the MCI firewall, even over IPv6). Domain fronting does not cut anything. ktest terminates the application's TLS itself and opens a **new** connection to the CDN edge with a harmless server name (for example `www.google.com`) in the ClientHello, a Chrome-like fingerprint and the application's own protocol (h2 or http/1.1). The edge routes by the request's Host / :authority, so YouTube answers although the wire only says google.com. The idea is the public MITM-DomainFronting project's; this is a Go re-implementation without Xray.

It needs the application to trust a local certificate authority, so it is **off until you set it up**:

```
ktest ca -install     create the CA and trust it for your Windows user (Windows asks you to confirm)
ktest ca              show its state
ktest ca -delete      stop trusting it and delete its key
```

**Cloudflare sites (X, Discord, Medium, npm) cannot be fronted this way**: Cloudflare answers 403 when the SNI and the Host differ. For them ktest uses Encrypted Client Hello, without any DNS: it sends a well-formed ECH configuration for `cloudflare-ech.com` that nobody holds a key for, the edge rejects it and returns the current configuration (retry_configs, authenticated for that name), and ktest handshakes again with it. The wire shows only `cloudflare-ech.com`; the real name travels encrypted. Any Cloudflare address serves any Cloudflare site, so a few built-in addresses are enough when DNS is poisoned. X's static files and video (`abs.twimg.com`, `video.twimg.com`) are on Fastly instead and use the Fastly route with the site's own address. Not every blocked site is on these CDNs: a site that is not listed is not fronted (the table is `DefaultFamilies` in `internal/front/rules.go`; unknown sites go through the other paths).

A CA is name-constrained when it is created and its list cannot be extended. If ktest learns new sites after you created it, `ktest ca` says so and `ktest ca -renew` replaces it.

What ktest does to keep this safe:

* The CA is **name-constrained** (critical X.509 name constraints) to the sites ktest can front: Google/YouTube, Meta (Facebook, Instagram, WhatsApp) and Fastly-hosted sites (Reddit, PyPI, ...). Even if its key leaked, no browser that honors constraints would accept it for a bank or a mail provider. The key lives in your user profile (`AppData/Roaming/ktest/ca`, or `KTEST_CA_DIR`), never in the portable folder.
* The connection to the edge is made and verified (certificate chain to the system roots, valid for the front, the site or the family) **before** the application is answered. If it fails, the application gets nothing and the other paths race as usual.
* Connect enables it only when the system reports the CA as trusted (`-front` forces it, `-no-front` forbids it). If applications keep refusing the certificate (Firefox has its own store: set `security.enterprise_roots.enabled` to true in about:config), fronting switches itself off after three refusals so nothing breaks.
* Several fronts are tried per family and ranked by what worked on your network, because a server name that is open on one operator is closed on the next. Add your own in `profiles/fronts.txt`: one line `family sni [dial]` (`-` = no SNI, `@own` = the site's own address). Diagnose tests every front without any certificate and shows which ones this network allows.

When no trusted address for a site exists at all (system DNS poisoned and encrypted DNS filtered, as in a field log from a filtered network), a family may carry edge address hints (Meta does): any address of the family's edge serves every site of the family. Google needs no DNS: the address of `www.google.com` serves YouTube and the rest.

Limits: only HTTPS on port 443 for the listed families; applications that pin certificates refuse it; Google may still refuse sanctioned content for an Iranian address, and fronting does not change your IP.

## 6. Whole PC (system-wide tunnel)

`ktest connect -tun` (menu 2) makes every application on the PC use ktest, with no proxy settings. A Wintun adapter driven by sing-box takes the TCP connections and hands each one, **by host name**, to the Connect proxy, so the same race (fronting, ECH, Xray, ByeDPI, cuts) decides per connection. Names are answered locally with fake addresses and mapped back when the connection arrives, so the poisoned system DNS is never used by applications; ktest then resolves the real address itself with its trusted chain.

What it does to be safe:

* It starts only after the proxy verified at least one site.
* It needs Administrator and asks Windows for it (UAC) instead of failing late.
* ktest and its cores (`xray.exe`, `ciadpi.exe`) are exempt from the tunnel and use the real interface; otherwise their own connections would loop. ktest also resolves names through the real network's DNS servers while the tunnel is up.
* The block-page range (`10.10.34.0/24`) goes to the proxy instead of the LAN; the proxy recovers the real name from the TLS SNI.
* Once the adapter is up it fetches two pages with `curl.exe` (a process that is not exempt, so the request takes the whole system path) and stops by itself if none works, printing what failed and sing-box's last lines. ktest's own requests would test nothing: it is exempt from the tunnel.
* The adapter does not use `strict_route`: that option blocks DNS on every other interface for every process, which would block ktest's own lookups. A DNS answer that still leaks out is at worst poisoned, and the proxy recovers the real name from the TLS SNI.
* Ctrl+C or Enter stops it and Windows restores its routes. UDP other than DNS is dropped, so applications fall back to TCP (browsers fall back from QUIC).

Telegram and other non-HTTPS protocols are carried like any TCP connection, but nothing here unblocks an address that is blocked by IP: that needs an exit outside the country, which no path in ktest provides yet.

Not verified on a real network: this mode changes Windows routes. It was checked for configuration validity (`sing-box check`) and by unit tests only.

## 7. WARP exit (optional)

Fronting and ECH reach sites on a few CDNs. Telegram, and anything blocked by IP address, needs a path that leaves from somewhere else. `ktest warp -enable` (menu 4, Setup, then 2) adds one: the open-source **Aether** core (AGPL-3.0, a separate process like Xray and ByeDPI) tunnels MASQUE over HTTP/2 to Cloudflare WARP and serves SOCKS5. Per the Patterniha channel MASQUE-H2 is the route that is open on every operator, and Aether fragments the ClientHello for the Irancell-type firewall and offers ECH for the MCI-type one, so two profiles run side by side.

* **Opt-in.** Enabling downloads Aether v2.3.0 (about 24 MB, SHA-256 pinned, from the project's GitHub release) if `cores/aether.exe` is missing, then registers a free, anonymous WARP identity on this PC, the same thing the WARP app does. The route to the WARP API (the key) is closed on some networks, so registration goes the way that is already known to work there: through the running ktest proxy if there is one; then with Encrypted Client Hello, using a configuration ktest fetched itself (a dummy one is rejected and Cloudflare answers with the real one, no DNS needed) and an edge address it reached; then plain; then fragmented. The same configuration is handed to the ECH profile when Connect runs Aether. The identity lives in your profile (`%AppData%\ktest\warp`) and `ktest warp -disable` deletes it.
* **Last resort, not a competitor.** Connect starts Aether in the background (its scan takes up to a minute) and adds it to the race when its port opens. For TLS it joins a connection only after every other path failed or 3 seconds passed, unless it is the path remembered for that site. For traffic that is not TLS (Telegram) only the direct route and the exit are tried, the outcome is remembered per destination, so a blocked address goes to the exit first the next time.
* **What it costs you.** Traffic that uses it passes through Cloudflare and leaves from a Cloudflare address (which also solves real sanctions, not the domestic filtering this tool is mostly about). `-no-warp` leaves it out of a session.

Not verified on a real network: it needs a registered identity, which was not created while building this, so Aether was only checked for its command line (`aether help`), not run end to end.

## 8. Advanced

Single methods (Xray fragment B/A on `127.0.0.1:10808`, ByeDPI on `127.0.0.1:10809`), the Cloudflare IP candidate scan and the experimental system-wide TCP TUN (Windows, Administrator, explicit `YES`). Connect makes these unnecessary for everyday use. The research commands (`probe`, `compare`, `edges`, `path`, `echo`, `access`, `revive`) are unchanged; see `ktest help`.

## 9. What is, and is not, possible

* Every path connects straight to the destination site. ktest needs no server of yours, and it does not change your public IP.
* Changing a byte of the ClientHello (rewriting the SNI, changing its case) is not possible for a transparent relay: the TLS handshake transcript would no longer match and the handshake fails. ktest cuts the ClientHello, it does not edit it.
* Fake packets with a low TTL need packet injection; they are available only through ByeDPI's own Windows implementation (the `fake` strategies).
* UDP and QUIC are not carried. Browsers fall back to TCP.
* A site whose IP address itself is blocked cannot be reached by any of these methods.
* No result in this repository comes from a measured Iranian ISP. `Diagnose` and the result box tell you what happens on **your** network, right now.

## 10. Where ktest looks for its files

`cores/` and `profiles/` are searched next to the executable, then in the working directory, `./dist/ktest-portable` and `./ktest-portable`. `KTEST_BASE` or `-base DIR` overrides it. `ktest strategies -write` creates the editable `profiles/byedpi-strategies.txt` (the packaged build ships it).

## 11. Output

Colors, box drawing and the in-place progress line are used only on an interactive terminal. In a pipe, a file, CI, with `NO_COLOR` or `TERM=dumb`, output is plain ASCII. Set `KTEST_ASCII=1` to force ASCII on a terminal that cannot show the glyphs.

## Options of `ktest connect`

None are needed. For experiments: `-v` (log every path decision and core output), `-listen`, `-strategies N`, `-no-xray`, `-no-self`, `-no-direct`, `-no-front`, `-front`, `-no-warp`, `-tun`, `-cert`, `-no-doh`, `-stagger`, `-first-byte`, `-ready`, `-base`.
