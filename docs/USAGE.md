# Using ktest

The everyday path needs no options and no knowledge of the methods behind it.

```
.\ktest.exe            menu: Connect, Diagnose, Advanced
.\ktest.exe connect    connect now
.\ktest.exe doctor     diagnose; changes nothing
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
2. Otherwise encrypted DNS is asked by IP literal (so no DNS is needed to find the resolver): Cloudflare `104.16.248.249`, `104.16.249.249`, `1.1.1.1` and Google `8.8.8.8`, `8.8.4.4`. All are tried at once, through every working path and the direct route, and the first answer wins. After three failures in a row encrypted DNS is skipped for five minutes, because it is itself filtered on many networks.
3. The Xray paths receive the trusted address too (they would otherwise need their own DNS, which is filtered the same way); if no trusted address exists they fall back to the name and use their own DNS.
4. For Google-owned names (youtube.com, ytimg.com, googlevideo.com, gstatic.com, ...) the address of `www.google.com` stands in, since Google front ends serve them; a path that cannot is simply a lost race.

## 4. Diagnose

`Diagnose` (or `ktest doctor`) checks the package, local ports and the network without starting anything, then measures:

* what the system resolver answers (and flags poisoning),
* whether each encrypted-DNS address completes a TLS handshake,
* a table of certificate-verified handshakes to a Google front end for an unblocked name (`www.google.com`) and a blocked one (`www.youtube.com`), each with the untouched ClientHello and each built-in cutting shape,
* a **verdict**. The important one: if the blocked name fails and every cut ClientHello also fails for the unblocked name, the network punishes cutting, so Xray fragment, ByeDPI split/slice and the built-in cuts cannot help; only methods that do not cut (fake packets with a low TTL, IPv6, QUIC) remain.

Run it once with any other VPN off and keep the output with your notes: it is the evidence for choosing methods.

## 5. Advanced

Single methods (Xray fragment B/A on `127.0.0.1:10808`, ByeDPI on `127.0.0.1:10809`), the Cloudflare IP candidate scan and the experimental system-wide TCP TUN (Windows, Administrator, explicit `YES`). Connect makes these unnecessary for everyday use. The research commands (`probe`, `compare`, `edges`, `path`, `echo`, `access`, `revive`) are unchanged; see `ktest help`.

## 6. What is, and is not, possible

* Every path connects straight to the destination site. ktest needs no server of yours, and it does not change your public IP.
* Changing a byte of the ClientHello (rewriting the SNI, changing its case) is not possible for a transparent relay: the TLS handshake transcript would no longer match and the handshake fails. ktest cuts the ClientHello, it does not edit it.
* Fake packets with a low TTL need packet injection; they are available only through ByeDPI's own Windows implementation (the `fake` strategies).
* UDP and QUIC are not carried. Browsers fall back to TCP.
* A site whose IP address itself is blocked cannot be reached by any of these methods.
* No result in this repository comes from a measured Iranian ISP. `Diagnose` and the result box tell you what happens on **your** network, right now.

## 7. Where ktest looks for its files

`cores/` and `profiles/` are searched next to the executable, then in the working directory, `./dist/ktest-portable` and `./ktest-portable`. `KTEST_BASE` or `-base DIR` overrides it. `ktest strategies -write` creates the editable `profiles/byedpi-strategies.txt` (the packaged build ships it).

## 8. Output

Colors, box drawing and the in-place progress line are used only on an interactive terminal. In a pipe, a file, CI, with `NO_COLOR` or `TERM=dumb`, output is plain ASCII. Set `KTEST_ASCII=1` to force ASCII on a terminal that cannot show the glyphs.

## Options of `ktest connect`

None are needed. For experiments: `-v` (log every path decision and core output), `-listen`, `-strategies N`, `-no-xray`, `-no-self`, `-no-direct`, `-no-doh`, `-stagger`, `-first-byte`, `-ready`, `-base`.
