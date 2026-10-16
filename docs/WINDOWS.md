# Windows portable — managed CLI (2026-10-15)

> **2026-10-16:** `docs/USAGE.md` is now the entry point. The menu has three screens (Connect, Diagnose, Advanced); the numbered list below describes the **Advanced** screen. `ktest auto` was removed (Connect replaces it) and `ktest smart` is now `ktest connect` (the old name still works). Later sections of this file are dated notes written while those features were built; where they differ, USAGE.md is current.

Use the latest successful `windows-portable` GitHub Actions artifact `ktest-windows-portable`; extract both ZIP layers fully. The complete folder includes `ktest.exe`, `cores/xray.exe`, `cores/ciadpi.exe`, `cores/sing-box.exe`, `cores/wintun.dll`, `profiles/Serverless-for-Iran.json`, and third-party license texts. Do not run just the executable extracted from the generic `verify` workflow.

Open Windows Terminal inside the extracted `ktest` directory and enter `.\ktest.exe`. Select using a single number and Enter.

- **1** Direct Xray Frag B; **2** Direct Xray Frag A; **3** ByeDPI adaptive; **4** ByeDPI TLS slicing. Selecting another mode stops the previous core first. The menu stays responsive while the core runs.
- After SOCKS starts, ktest compares **YouTube and Google via SOCKS and directly**, with verified HTTPS. A `CANDIDATE` means only the SOCKS route worked in this controlled comparison; it is not proof of the censorship mechanism. The user must disconnect other VPNs independently before interpreting an ISP-path result. There is no VPN-process or adapter detection.
- **5** scans up to 300 dispersed Cloudflare IP candidates from the official CDN ranges until 10 HTTPS responses are TLS-verified or the budget is exhausted. Ctrl+C cancels; this is not proof of third-party fronting.
- **6** toggles *experimental system-wide TCP TUN* on Windows via official sing-box 1.14.3 + signed Wintun 0.14.1. The option is disabled unless a current proxy has at least one verified HTTP result. Must run Windows Terminal **as Administrator**. TUN changes Windows routes; explicit `YES` is required; TUN is stopped automatically if direct website checks fail. Only TCP is forwarded through the local SOCKS; UDP other than DNS is blocked. This is not a complete UDP VPN or a guaranteed way to connect Windscribe.
- **7** stops the selected core (and any TUN) without closing the menu. **8** retests the targets through the current SOCKS proxy. **0** stops everything and exits. Ctrl+C is intercepted to request stop rather than immediately terminating the launcher. If the TUN process is forcibly killed or the machine crashes, inspect network adapters/routes and restart Windows if connectivity does not recover.

This tool does **not** silently change global proxy settings. Without TUN, explicitly set application SOCKS5 to `127.0.0.1:10808` for Xray or `127.0.0.1:10809` for ByeDPI. In Firefox, set `Settings > General > Network Settings > Manual proxy`; enable proxy DNS over SOCKS5. The proxy is not an external VPN, and the public IP may stay Iranian.

**Operational limitations**:
- No live Iranian ISP measurements have been made in CI. Both automatic checks may fail in filtered networks even when the program launches correctly.
- Windows TUN is a *beta* integration, not an independently field-validated setup. It selects an apparent physical NIC and uses process-based physical-bypass rules; do not combine with another VPN while trialing it. Upstream sing-box issues documented DNS/TUN packet loops on Windows, hence the guard for TUN CIDRs. Some device adapters or enterprise firewalls may reject route modifications.
- A regular TCP/IP proxy cannot make a separate UDP WireGuard transport work. Global TUN in this stage intentionally rejects most UDP; it is not appropriate for gaming, WireGuard/QUIC, or reliable all-protocol VPN.
- The Xray/ByeDPI settings are derived from public projects and may be stale for any specific ISP. `PASS` only confirms successful HTTP transport for the tested host, not all of YouTube's media domains.
- All additional binaries are downloaded on GitHub Actions from upstream versioned assets and SHA-256 verified. Redistribute license notices with the executable files.


## 2026-10-15 update: DNS and CDN operations

Before Fragment A/B, ktest sends actual Google Public DNS TXT identity queries to **8.8.8.8:53** using UDP and TCP. DNS reachability is not determined by Ping. When the Google identity TXT succeeds, an optional last-resort Google DNS resolver is added to Xray's profile, after encrypted Google DoH and before Cloudflare DoH; no Windows DNS setting is changed. Plaintext DNS can be interfered with and should not be confused with DoH or encrypted browsing. The absence of an answer does not prevent choosing another method.

Menu #5 scans up to 300 diverse official Cloudflare IPv4 candidates, six concurrent HTTPS requests maximum, and tries to find 10 *real TLS-verified provider HTTPS* responses. Ctrl+C cancels. The output **does not** establish that SNI/Host domain fronting works for other websites. CLI: `ktest scan -provider cloudflare -limit 100` or increase to 300. A small Akamai/Google/Fastly list is still available through flags.

**Windscribe heuristics were removed on request.** The app no longer checks the Windscribe process or VPN adapters, and it no longer blocks scanning based on them. For interpretable ISP results, disconnect any other VPN yourself. Proxy-vs-direct website results are still compared, but attribution assumes the user controlled the network state.


## 2026-10-16 update: `auto`, `doctor` and startup fixes

- `ktest auto` tries Xray Fragment B, Fragment A, ByeDPI adaptive and ByeDPI TLS slicing in order. Each is started, verified with real HTTPS requests through its own proxy and compared with the direct route; the first method that passes every target stays running until Ctrl+C. Options: `-methods 1,2,3,4`, `-hold=false` (verify and exit), `-v` (show core logs), `-ready 45s`. Exit code 1 means no method could be verified; the output lists each method's reason. It never changes system proxy, DNS or routes.
- `ktest doctor` changes nothing. It checks the package files, the Xray version, both profile variants, ports 10808/10809, a real Google DNS query and direct YouTube/Google reachability, and says which layer to fix first.
- Port conflicts are now detected before launch. v2rayN also defaults to 10808/10809, and an orphaned `xray.exe` keeps its port. Previously the readiness probe connected to that foreign listener and the website check measured someone else's proxy.
- The menu waits up to 45 s for a core's port instead of a fixed 7 s, and no longer repeats the DNS preflight. The preflight runs in the background, so a network that drops 8.8.8.8 no longer freezes the menu or Ctrl+C. UDP and TCP DNS probes run in parallel.
- `ktest path -connect` runs its DNS lookup concurrently with TCP/TLS. A hanging resolver can no longer consume the whole timeout and report a working pinned address as `tcp_unavailable`.
- CDN candidate IPs no longer end in `.0` or `.255`.

### Editable ByeDPI strategies

`ktest auto` now tries `1,2,s` by default. `s` expands to every line of `profiles/byedpi-strategies.txt` (`label | ciadpi arguments`; `#` comments). Without that file the built-in list is used. `ktest strategies` prints the effective list and `ktest strategies -write` creates the editable file (the portable package ships it). ktest always supplies `-i 127.0.0.1 -p 10809`; lines that set `-i/--ip/-p/--port/-D/--daemon/-w/--pidfile` are rejected. The shipped candidates come from the ByeDPI documentation and are not measured on any ISP; only a strategy that passes the real HTTPS checks on the current network is kept. Each failing strategy can cost up to about 16 s, so trim the list for faster runs.

## 2026-10-16: `ktest smart` (path racing)

Hypothesis, not a field-validated result: censorship differs per site and per network, and any single anti-DPI method drifts out of date, so one global choice is fragile. `ktest smart` starts Xray Fragment B (port 10808), Fragment A (10811) and the first N ByeDPI strategies (10812+, `-strategies 3`) side by side, and puts one loopback SOCKS5 listener in front of them (`127.0.0.1:10800`, `-listen`).

For every TLS connection the proxy reads the ClientHello, sends it over the paths in learned order (the path that last worked for that host first, then by wins and latency), starts the next path after `-stagger` (300 ms) or immediately when the previous one failed, and accepts the first path that answers with a TLS handshake record. Nothing has been sent to the application before that, so a failed or silently dropped attempt is replayed on another path without the application noticing. The TLS session stays end-to-end: the application verifies the certificate; no CA is installed. Non-TLS connections use the best-ranked path without racing. `-direct` adds the ordinary system route as one more racer (it uses local DNS).

Scope and limits: it can only choose among paths that already work for some sites; it does not repair IP-level blocking or allowlisting. A ClientHello for the same site may be sent over several paths at once, which the local ISP already sees. UDP/QUIC is not supported (SOCKS5 CONNECT only). Which path last worked per host is kept in memory only and printed on exit. Applications must use the SOCKS5 address with remote/proxy DNS enabled. Verified locally against the real cores on a network without filtering (selftest passes, different paths win different sites); not yet verified on a filtered network.

Encrypted DNS for ByeDPI paths: ByeDPI and the direct route resolve names with the Windows resolver, which many filtered networks poison (YouTube resolving to a private address), so on such a network those paths cannot work even when their desync method would. `ktest smart` therefore resolves the name itself over DNS-over-HTTPS (dns.google, then Cloudflare; certificates verified; carried through an Xray path when one is up) and gives those paths the IP, while Xray paths keep receiving the name. Lookups are cached, shared between racers and not cancelled when a race ends. `-no-doh` turns this off. The SNI inside the ClientHello is unchanged. `ktest auto` still hands ByeDPI the name, so it can under-report ByeDPI on a DNS-poisoned network; use `ktest smart` there.

### Built-in ClientHello cutting (`self:` paths) and DoH safety

DoH/DoT is itself filtered on many networks, so it must never be a dependency. The resolver gets at most 1.5 s per attempt; after three consecutive failures it is skipped for five minutes and the system resolver is used, then probed again. Xray paths never depend on it.

`ktest smart` also adds four paths implemented inside ktest (no external core, no raw sockets, no administrator rights; `-no-self` removes them). They connect directly and differ only in how the ClientHello is cut: two TCP segments split inside the SNI, two TLS records split inside the SNI, records plus separate segments, and three records in three segments. Cut points and pauses are drawn at random for every connection, so there is no fixed byte or timing pattern, and the race learns per site which family the current network tolerates. All output is valid TLS/TCP (a ClientHello may be fragmented over records and segments); tests complete real TLS handshakes with every family. Whether any of them defeats a given filter is an empirical question for the target network; they only cost a duplicate flight when they lose.

### Field notes from the Patterniha Telegram channel (https://t.me/patt_channel_x, read 2026-10-16)

Secondary, dated, per-operator reports; treat them as hypotheses to measure, not guarantees. The channel is in Persian and publishes times without calendar dates.

- Fragmentation is reported fully blocked on Hamrah-e Aval (MCI), IPv6 included, so Xray Fragment A/B and our `self:` cutting paths are not expected to help there. Reported alternatives there: CDN routes via ECH or IPv6, and MASQUE over HTTP/2.
- Irancell is reported to accept fragment + fingerprint for Cloudflare CDN routes, while throttling the ECH domain's upload.
- Serverless v52 is described as needing IPv6, and only for YouTube-style access. This is why `ktest smart` now includes two IPv6 twins (`self6:`) of the record-splitting families, resolving AAAA records, and races them against the IPv4 paths. The machine used for development has no global IPv6, so these were unit-tested only and could not be exercised live.
- ECH and Cloudflare-specific tunnel settings from the channel need a TLS-terminating client; a transparent relay like `smart` cannot add them. MITM-DomainFronting is the channel's suggestion for direct YouTube; ktest does not install a CA, so that stays out of scope.

### Menu item 9: Smart

The interactive menu now has **9) Smart**, the same session as `ktest smart`: all Xray, ByeDPI and built-in paths start together and applications use one SOCKS5 address, `127.0.0.1:10800` (enable remote/proxy DNS). Items 1-4 remain for forcing a single method. Item 9 needs no server of your own: every path connects straight to the destination site and only changes how the first TLS flight is sent. Stopping (7, Ctrl+C or 0) prints which path won for which site, kept in memory only.

### Running from source with `go run`

`go run ./cmd/ktest` (or `go run ./cmd/ktest smart`, `doctor`, `auto`) works without building an exe. The portable folder (`cores/`, `profiles/`) is looked up next to the exe, then in the working directory, `./dist/ktest-portable` and `./ktest-portable`; `KTEST_BASE` or `-base DIR` overrides it. Use Windows Terminal in the repository folder.

## 2026-10-16: field log analysis and redesign of `smart`

A real run on a filtered network (VPN off) showed: `8.8.8.8` UDP and TCP unreachable, DoH timeouts for dns.google and cloudflare-dns.com (also inside Xray's fragment outbound), YouTube failing through all 11 paths, and even the unblocked Google failing through Xray A/B and ByeDPI "TLS record slicing" while working directly and through ByeDPI "adaptive" (which sends the first attempt uncut). Reading that as a network engineer:

1. **DNS was never solved.** The system resolver is poisoned for blocked names and every public resolver is filtered by name or address, so no path ever received the real address of YouTube. Fixed with a trusted resolver chain: system answers are screened for private/reserved block-page addresses (`10.10.34.x` and friends); encrypted DNS is then asked by IP literal (Cloudflare 104.16.248.249 / 104.16.249.249 / 1.1.1.1, Google 8.8.8.8 / 8.8.4.4) over every working path and the direct route at once, first answer wins; encrypted DNS is skipped for five minutes after three consecutive failures; finally, for Google-owned names the address of www.google.com is used (Google front ends serve these names; a path that cannot is just a lost race). A poisoned answer is never dialed.
2. **Cutting the ClientHello can itself be punished.** On such a network every cutting path fails, including for unblocked sites. The uncut connection (`plain: no cutting`) now takes part in the race and has the first head start, so unblocked sites never pay for a cut hello.
3. **The default strategy set was monoculture.** `smart` ran only the first three ByeDPI strategies, all splitting. It now runs the whole list (up to 12) and the file is ordered across mechanisms: adaptive, fake packet, fake with low TTL, split+disorder, out-of-band, record slicing.
4. **No diagnosis existed.** `ktest doctor` now characterizes the network: what the system resolver answers (and flags poisoning), whether each encrypted-DNS address completes a TLS handshake, and a matrix of certificate-verified handshakes to a Google front end for an unblocked SNI (www.google.com) and a blocked one (www.youtube.com) with the uncut ClientHello and each cutting shape, followed by a verdict. `-no-net` skips it. Run it with other VPNs off and compare.

Not possible without a cooperating client or privileged packet injection: rewriting SNI or casing inside the ClientHello. Any changed byte invalidates the TLS transcript (the Finished messages), so a transparent relay can only cut the hello, not edit it. Fake packets with a low TTL need raw packet injection (WinDivert/administrator) or ByeDPI's own Windows implementation, which is why those strategies stay as separate cores.

## 2026-10-16: domain fronting (supersedes the "MITM-DomainFronting stays out of scope" note above)

Sources read: the channel posts of 28 Sep to 16 Oct 2026, patterniha/MITM-DomainFronting (config v23, 23 releases, the issue tracker), its forks (mirrors and one Windows GUI wrapper, MITMConnect), and the SNI-Spoofing family (patterniha's original, snix, SNISPF, sni-spoofing-rust/Go).

What the sources say, and what ktest took from them:

- **MITM-DomainFronting** terminates the browser's TLS with a local CA and re-originates it to the CDN edge with a whitelisted SNI (` www.google.com ` for Google, a Fastly-hosted name for Reddit/PyPI/GitHub assets, ` www.microsoft.com ` for Meta). Reimplemented natively as `internal/front`: no Xray, h2 and http/1.1 relayed unchanged, Chrome fingerprint via uTLS, the application's ALPN mirrored upstream.
- **The reference's weaknesses, fixed here.** Its CA is unconstrained and valid for about a century (the README warns never to share the key); ours is name-constrained, two years, stored per user. It answers the browser before knowing the edge works; ours verifies the edge first and falls back to the other paths. It has one hard-coded SNI per CDN, and the tracker shows that this breaks per operator and per week (python.org vs pypi.org on MCI); ours keeps several fronts per family, ranks them by what worked, and lets `profiles/fronts.txt` add more. Its DoH to 1.1.1.1 fails on Irancell (issue 163); ours does not need DNS for Google at all (the edge address of www.google.com is dialed when the site's own address is poisoned).
- **SNI-Spoofing** (fake ClientHello with a wrong TCP sequence number, injected with WinDivert) is not implemented: it needs a kernel driver and administrator rights, and the tools are fixed-upstream forwarders, not general proxies. ByeDPI's fake/TTL strategies remain the packet-injection route. snix's good ideas were kept as design: per-flow rotation, an SNI pool and an SNI scan (here: the fronts list and the Diagnose probe).
- **Not implemented, and why.** ECH (the channel's MCI recommendation for Cloudflare-hosted sites) and MASQUE/WireGuard-over-MASQUE to Cloudflare WARP need a TLS-terminating client; ECH is now feasible on top of the same takeover mechanism (Go's TLS client supports it) and is the natural next step, WARP/MASQUE is a separate tunnel. Worker/edgetunnel setups need a Cloudflare account of your own.
- **Field state per the channel (unverified here):** fragmentation fully blocked on MCI (even IPv6); Irancell: fragment plus a Python-like cipher-suite fingerprint works for Cloudflare, ECH has strongly limited upload; MASQUE-H2 reported open everywhere. Fronting to Google/Meta/Fastly edges does not depend on any of these, but it can be closed by an operator that whitelists by IP, which is what Diagnose measures.

Live checks on a development machine with unfiltered access (so these prove the mechanism, not the bypass): through the proxy with only the front path enabled, www.youtube.com, www.google.com, www.instagram.com (no SNI), www.reddit.com and pypi.org (SNI pypi.org) all answered with the certificate chain verified, and a Go HTTP/2 client fetched the YouTube home page, a thumbnail from i.ytimg.com, Google, Reddit and Instagram over h2 end to end.
