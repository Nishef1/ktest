# Using ktest

The everyday path needs no options and no knowledge of the methods behind it.

```
.\ktest.exe                 menu: six policies, separate coverage, Diagnose, Setup, CDN/Windscribe tests
.\ktest.exe connect         connect with saved preferences (first Windows launch: TUN)
.\ktest.exe connect -cert   set up or renew the fronting certificate, then connect
.\ktest.exe connect -tun    Whole PC TCP coverage for the chosen policy (asks for Administrator)
.\ktest.exe connect -tun=false  use Proxy coverage and remember that choice
.\ktest.exe doctor          diagnose; changes nothing
```

From source: `go run ./cmd/ktest` (see "Where ktest looks for its files").

On Windows, a first launch defaults to **TUN**; other platforms default to Proxy because this TUN integration is Windows-only. Menu option 7 shows `Current Mode: TUN` or `Current Mode: Proxy` and saves a change immediately. Its submenu marks the current choice and confirms a successful save. Closing the window does not lose it. Windscribe always uses its own VPN and does not change the saved coverage of other policies.

The menu keeps keys 1–11 and 0. **Enter connects with the saved policy** (Balanced on a first launch). Keys 1–6 choose a connection family; Aether and Windscribe open their method submenus first. `Last used` and the disconnected status describe the current process, not a running VPN in another window. Reopening the menu never connects automatically. During a connection, Enter or Ctrl+C disconnects and returns to the menu; Ctrl+C on the idle menu exits. Setup shows configuration details and actionable notices separately from verified network readiness.

Ctrl+C in a submenu goes back one level; only the idle **main** menu exits the application. Setup remains open after returning from Certificate or Exit paths. It checks local certificate/key integrity, validity dates, coverage of the current fronting domains and the operating system's trust check each time it is displayed. A healthy certificate is green (`Installed / trusted / up to date`); expiration within 30 days, invalid dates or old domain coverage offer `Renew`. Missing files offer Install; a usable certificate without system trust offers Install trust. Broken/partial files show Repair. The Certificate page always allows explicit renewal of a healthy CA as well. Reading status never installs, renews or deletes certificates.

On a terminal with VT support and at least 60 columns by 24 rows, menu/coverage navigation redraws on an alternate screen. Starting a connection or opening a tool restores the normal screen, preserving connection logs and scrollback. Small terminals, pipes, `NO_COLOR` and `TERM=dumb` keep a scrollable transcript. The main menu fits a 24-row screen at standard widths; narrow displays wrap descriptions.

Preferences live in the current user's configuration directory: `%APPDATA%\ktest\settings.json` on Windows (`KTEST_SETTINGS_FILE` can select another file). The menu and `connect` use the same saved options; explicit connection flags override and update their saved values. This includes ports, path switches, timings, extra protected AI domains and Windscribe carrier settings. Mode-specific settings remain stored but apply only to compatible policies. The certificate-offer skip choice and the defaults shown in Diagnose, CDN scan and Windscribe test also survive restart. In tool prompts, Enter accepts the displayed previous value; `-` clears a saved optional CDN/target. Certificate generation/install (`-cert`), active connections, Administrator permission and credentials are never saved as repeatable actions. An unreadable or invalid preferences file is preserved and reported; that session uses defaults and reports that changes cannot be saved.

Administrator relaunches receive the complete effective connection policy, including saved extra AI domains and disabled paths. They do not depend on another administrator account having the same preferences, and do not overwrite that account's settings or repeat certificate installation.

## 1. Connect

Connect starts every available method at once and puts **one** local SOCKS5 address in front of them: `socks5://127.0.0.1:10800`. It also exposes a loopback HTTP CONNECT proxy at `http://127.0.0.1:10801` for clients such as Windscribe that accept an HTTP upstream proxy. Both share the same path-selection engine; `-no-http` disables the optional HTTP listener and `-http-listen 127.0.0.1:10802` changes its port. To add a working external SOCKS5 exit as a last resort, use `-exit-socks 127.0.0.1:<port>` (loopback only; not the ktest ports). **Windscribe setup:** see [WINDSCRIBE_BOOTSTRAP.md](WINDSCRIBE_BOOTSTRAP.md) and use **Proxy Settings**, not **Proxy Gateway**. This bridge carries TCP, not WireGuard/IKEv2 UDP, and an HTTP page working is not proof that a VPN tunnel is established. Point an application at it and turn on "proxy DNS" / remote DNS (in Firefox: Settings → Network Settings → Manual proxy → SOCKS Host `127.0.0.1`, Port `10800`, SOCKS v5, and tick "Proxy DNS when using SOCKS v5").

The screen shows four phases with a percentage and a final state:

| Phase | What happens |
| --- | --- |
| Checking the network | System DNS is asked for `www.youtube.com`; a private answer such as `10.10.34.x` is reported as **poisoned**. The public resolver 8.8.8.8 is probed with a real query. |
| Starting external paths | Xray fragment A and B and the ByeDPI strategies from `profiles/byedpi-strategies.txt` start side by side. A bar shows how many are ready; a core that cannot start is listed with its reason. |
| Representative site checks | YouTube, Google, Wikipedia, Telegram and Discord are checked through the proxy and directly. Each group has at most three concurrent checks and one shared eight-second budget. The first two request tiny 204 endpoints; the others use HEAD. TLS verification stays on. |
| Result box | **READY** (all reachable), **PARTLY READY** (some), **NOT VERIFIED** (none). It also says whether a site was blocked directly and open through ktest (*bypass confirmed*) or open both ways (nothing to bypass; if another VPN is on, turn it off to see a bypass). |

The result box appears after requested TUN coverage has been checked and states whether TUN is active or only the proxy is available. The live list shows a destination when its route, outcome, or slow/fast state changes. Enter or Ctrl+C disconnects and prints separate response, refusal, TCP-only, and route-setup counts, rather than an application-success percentage inferred from TLS alone.

These checks exercise normal destination racing and seed its hostname/port history. They do not download full pages or exhaustively benchmark every route for every service. Only a failing/slow initial route expands to alternatives. HTTP 403 and similar service responses are reported separately from reachability failures; an unattempted direct control never counts as bypass proof. Probes have no account cookies and do not follow redirects. AI/account services are excluded from these direct controls.

Every 15 minutes, a session with traffic since its last check repeats only the five proxied checks, sharing an eight-second client budget. Idle sessions send no refresh probes. Internal calibration connections are tagged separately, so even late results cannot count as user activity or enter live traffic statistics; genuine user activity during a refresh remains eligible for the next interval. Normal connection failures still affect route selection immediately. Windscribe runs neither these website checks nor their refreshes. Strict exit modes wait up to 20 seconds for a verified exit before initial checks; they never substitute a direct route.

Proxy coverage only writes per-user preferences; it does not change system proxy, DNS, routes, firewall or certificate trust. Requested TUN coverage changes routes only while its verified tunnel runs; certificate setup is an explicit separate action. On Windows ktest runs inside a kill-on-close job object, so closing the window or killing ktest also ends every core and frees the ports.

## 2. How the methods are chosen

Choose policy and coverage first (see CONNECTION_MODES.md). Within routes permitted by that policy, ktest adapts to the destination and network. Balanced/Fast can race:

* **Paths.** `plain` (the untouched connection, where the selected policy permits a direct route), `plain6` (the same over IPv6), the Xray profiles, the ByeDPI strategies (adaptive, fake packets, low TTL, split + disorder, out-of-band, TLS record slicing), and three built-in families that cut the ClientHello inside the SNI over TCP segments and/or TLS records, with random cut points and pauses per connection (plus IPv6 twins).
* **Staged racing.** Each TLS connection starts with its preferred path. Its adaptive head start is bounded by the configured stagger (125 ms in Fast, 250 ms by default in Balanced); a slow remembered route cannot impose an extra second of exclusive waiting. After this head start or an immediate failure, up to three normal candidates run concurrently. If those remain silent, the remaining normal routes join after another 250 ms; the separate last-resort gate for Late exits remains in effect. A good route near the front can answer without opening every configured route, while a deeply ranked working route still gets a bounded fallback opportunity.
* **Response validation.** A route must return a complete, structurally valid ServerHello, including when it spans TLS records. A record header alone cannot win. This checks framing; the application still authenticates TLS and decides whether the service is usable. Once server bytes reach the application, requests are not replayed onto another route.
* **Ranking and stability.** Success, failures, and latency are learned for each exact hostname and port. One transient failure does not erase a proven preference. Repeated failures temporarily demote a route; replacing a healthy preferred route requires repeated wins with a substantial latency improvement. A prompt upstream close with no post-hello response data is reported separately; two such observations temporarily demote the route for later connections. Client-initiated closes, small TLS alerts, and canceled races are inconclusive and do not count as these failures.
* **Memory.** Exact `host:port` history expires after 30 minutes of inactivity and is kept only in memory. A sibling hostname's preferred route is an initial hint for a fresh destination, including new `googlevideo.com` nodes; it never overwrites another hostname's established history. Nothing about visited sites is written to disk. Protected exit policies remain pinned to their first selected verified foreign route, including during concurrent connections.

When an application refuses a fronting takeover, that route is demoted for that exact destination for one minute. An available alternative is preferred on the next connection; the refused application's request is never replayed. Certificate verification stays enabled.

The exit summary reads current registered/verified counts when it is rendered and reports whether discovery is continuing or complete. Dead managed exit cores are deregistered even while other profiles are being searched. Both Fast and Balanced require verified foreign exits for known AI domains, including ChatGPT/OpenAI, Gemini and Claude, and fail closed without one. Plain, fragment and fronting paths cannot carry those destinations. The old `-ai-direct` opt-out is removed. Windscribe's bootstrap listeners reject direct AI use; the Windscribe application owns its VPN traffic.

Foreign verification is refreshed on demand before protected traffic when its five-minute lease expires, using the neutral HTTPS trace endpoint through the individual exit. Concurrent requests share a refresh; failed/unknown geolocation blocks protected dials and is briefly backed off. Protected SNI also takes precedence over an ordinary SOCKS hostname. This is a sampled GeoIP check, not a guarantee that a provider never changes an IP or uses different exits for different destinations. The policy covers traffic routed through ktest whose hostname/SNI can be identified; it cannot control other applications bypassing the proxy.

TLS ClientHello messages are assembled across record boundaries before routing; incomplete or malformed handshakes fail without an upstream attempt. Extra client records are reserved for the selected route. In mixed modes, an otherwise unprotected destination must supply initial client bytes within two seconds: an empty timeout cannot select a direct route before a later protected SNI arrives. Server-first protocols without that initial identity require a verified foreign-only mode. Known protected hostnames and strict foreign-only modes retain server-first operation through verified exits.

## 3. Names (DNS)

Name resolution is the first thing a censor poisons, so it is not left to the system resolver alone:

1. The system answer is used when it is a real address. Private or reserved addresses are treated as poisoning and never dialed.
2. Otherwise encrypted DNS is asked. Where the public resolvers are filtered by address (1.1.1.1, 8.8.8.8, the Cloudflare CDN addresses all reset), Cloudflare's resolver is reached through Encrypted Client Hello from ktest itself, with no DNS and no certificate: the wire shows only `cloudflare-ech.com`. This is what gives every path the real address of a site, YouTube's video servers included (a stand-in address serves the page but answers `404` to a video request). The public resolvers are also asked by IP literal (so no DNS is needed to find the resolver): Cloudflare `104.16.248.249`, `104.16.249.249`, `1.1.1.1` and Google `8.8.8.8`, `8.8.4.4`. The last successful resolver endpoint is tried first; two alternatives join after 150 ms and all remaining endpoints after 400 ms if needed. A failed endpoint advances immediately. HTTPS connections are reused across names, with at most four connections per endpoint, instead of opening every endpoint and every carrier for each name. After three failures in a row encrypted DNS is skipped for five minutes, because it is itself filtered on many networks. Cloudflare's 1.1.1.1 and 1.0.0.1 are also asked under a decoy server name (`www.microsoft.com`), as the MITM-DomainFronting project does; the certificate is still verified for Cloudflare's real names.
3. The Xray paths receive the trusted address too (they would otherwise need their own DNS, which is filtered the same way); if no trusted address exists they fall back to the name and use their own DNS.
4. For Google-owned names (youtube.com, ytimg.com, googlevideo.com, gstatic.com, ...) the address of `www.google.com` stands in, since Google front ends serve them; a path that cannot is simply a lost race.

## 4. Diagnose

`Diagnose` (or `ktest doctor`) checks the package, local ports and the network without starting anything, then measures:

* what the system resolver answers (and flags poisoning),
* whether each encrypted-DNS address completes a TLS handshake,
* a table of certificate-verified handshakes to a Google front end for an unblocked name (`www.google.com`) and a blocked one (`www.youtube.com`), each with the untouched ClientHello and each built-in cutting shape,
* a **verdict**. The important one: if the blocked name fails and every cut ClientHello also fails for the unblocked name, the network punishes cutting, so Xray fragment, ByeDPI split/slice and the built-in cuts cannot help; only methods that do not cut (fake packets with a low TTL, IPv6, QUIC) remain.

These are samples, not proof that every SNI/path is blocked or that a VPN authenticated. The Diagnose menu separates general checks, Windscribe prerequisites, bounded Aether comparison (with optional small-transfer samples), and saved network recommendations. Enter/Ctrl+C cancels a running diagnosis. doctor -no-net skips external network probes. See [NETWORK_DIAGNOSIS.md](NETWORK_DIAGNOSIS.md) for method families, budgets and cache policy.

For Windscribe, doctor -mode windscribe checks local carrier prerequisites, bridge ports, conflicting ktest TUN interfaces, CLI state/protocol and basic API DNS. Imported Xray subscriptions, fronting certificates and foreign exits are not required. It cannot inspect the app Proxy Settings UI or authenticate OpenVPN. Missing optional cores disable their own paths; they do not prove all connection methods failed.

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

CA and leaf-key generation are entirely local and offline using the operating system's secure randomness. Each independent user installation generates its own key and certificate; private keys are not bundled or shared. Trust installation is separate: Windows user confirmation is retained, and a trusted existing CA is reused without repeating setup. This repository's portable TUN package is Windows-only; installing a CA on a phone neither runs that package nor makes every mobile app trust user-added certificates.

What ktest does to keep this safe:

* The CA is **name-constrained** (critical X.509 name constraints) to the sites ktest can front: Google/YouTube, Meta (Facebook, Instagram, WhatsApp) and Fastly-hosted sites (Reddit, PyPI, ...). Even if its key leaked, no browser that honors constraints would accept it for a bank or a mail provider. The key lives in your user profile (`AppData/Roaming/ktest/ca`, or `KTEST_CA_DIR`), never in the portable folder.
* The connection to the edge is made and verified (certificate chain to the system roots, valid for the front, the site or the family) **before** the application is answered. If it fails, the application gets nothing and the other paths race as usual.
* Connect enables it only when the system reports the CA as trusted (`-front` forces it, `-no-front` forbids it). If applications keep refusing the certificate (Firefox has its own store: set `security.enterprise_roots.enabled` to true in about:config), fronting switches itself off after three refusals so nothing breaks.
* Several fronts are tried per family and ranked by what worked on your network, because a server name that is open on one operator is closed on the next. Add your own in `profiles/fronts.txt`: one line `family sni [dial]` (`-` = no SNI, `@own` = the site's own address). Diagnose tests every front without any certificate and shows which ones this network allows.

The certificate screen in Setup shows whether fronting is enabled. `ENABLE` / `DISABLE` saves that routing choice without changing the certificate or system trust. Installing or renewing the CA alone does not override a saved `-no-front`. Balanced/Fast search all Aether exit methods automatically, independently of a method saved in the Aether submenu; an explicit `connect -aether-method ...` still isolates a method for experiments.

When no trusted address for a site exists at all (system DNS poisoned and encrypted DNS filtered, as in a field log from a filtered network), a family may carry edge address hints (Meta does): any address of the family's edge serves every site of the family. Google needs no DNS: the address of `www.google.com` serves YouTube and the rest.

Limits: only HTTPS on port 443 for the listed families; applications that pin certificates refuse it; Google may still refuse sanctioned content for an Iranian address, and fronting does not change your IP.

## 6. Whole PC (system-wide tunnel)

Whole PC is coverage, separate from the six policies. Menu 7 selects Proxy apps or Whole PC TCP; then choose policy 1-4 or 6. CLI example: ktest connect -mode aether -tun. The policy survives Administrator elevation. A sing-box/Wintun adapter forwards public TCP to the selected policy; LAN and helper processes are exempt. It does not create a fixed public IP or a persistent kill switch. Windscribe uses its own coverage and cannot share this TUN.

What it does to be safe:

* It starts only after the proxy verified at least one site.
* It needs Administrator and asks Windows for it (UAC) instead of failing late.
* ktest and its cores (`xray.exe`, `ciadpi.exe`) are exempt from the tunnel and use the real interface; otherwise their own connections would loop. ktest also resolves names through the real network's DNS servers while the tunnel is up.
* The block-page range (`10.10.34.0/24`) goes to the proxy instead of the LAN; the proxy recovers the real name from the TLS SNI.
* Once the adapter is up it fetches two pages with `curl.exe` (a process that is not exempt, so the request takes the whole system path) and stops by itself if none works, printing what failed and sing-box's last lines. ktest's own requests would test nothing: it is exempt from the tunnel.
* The adapter does not use `strict_route`: that option blocks DNS on every other interface for every process, which would block ktest's own lookups. A DNS answer that still leaks out is at worst poisoned, and the proxy recovers the real name from the TLS SNI.
* Ctrl+C or Enter stops it and Windows restores its routes. Public UDP other than DNS is rejected with ICMP port unreachable, allowing applications to fall back from QUIC to TCP without waiting for silent packet-loss timeouts. Applications that require UDP still cannot use these TCP-only paths. TUN startup waits for the adapter to come up instead of sleeping for a fixed five seconds, then checks real HTTP requests whose Windows source address must belong to the TUN adapter. Environment HTTP proxies are disabled for these probes.

Telegram and other non-HTTPS protocols can be carried as TCP. IP-blocked destinations may require a working foreign exit; packet cutting alone cannot guarantee access. Available exits and direct fallback depend on the selected policy.

Not verified on a real network: this mode changes Windows routes. It was checked for configuration validity (`sing-box check`) and by unit tests only.

## 8. The menu

Example after selecting Fast; on a first launch the default policy is Balanced:

```
ktest  Free access toolkit
  Disconnected · Last policy: Fast
────────────────────────────────────────────────────────────────
  Enter  Connect with Fast

  CONNECTION METHODS
   1  Balanced            Adaptive routing
   2  Fast                Faster fallback · Last used
   3  Aether              WARP / Psiphon
   4  Aether to Tor       Tor
   5  Windscribe          Bridge for the Windscribe app
   6  Aether to Psiphon   Psiphon
  COVERAGE
   7  Current Mode: TUN
  TOOLS
   8  Diagnose            Check connection problems
   9  Setup               Certificates and exit components
  10  CDN scan
  11  Windscribe test

   0  Exit
────────────────────────────────────────────────────────────────
  Enter to connect · number to choose an option
  Select >
```

`Aether` opens connection/method/diagnosis choices for MASQUE H2/H3, WireGuard, Gool, classic WARP-in-WARP, MASQUE-in-MASQUE and Psiphon. `Aether to Psiphon` selects only the normal/CDN Psiphon profiles, while `Aether to Tor` uses Aether's Tor-only backend. Menu 5 separates local-only Windscribe from explicit Windscribe through Aether. Menu 11 groups prerequisites, WStunnel/Stealth comparisons, real bridge observation, Aether comparison/carrier, connected VPN data and owned CDN tests.

Every submenu accepts `0`, `b`, or `back`; Ctrl+C goes back one level. An invalid choice stays in the same tool. At the CDN hostname and Windscribe SNI prompts, Back returns to the provider/target prompt. Completed or cancelled diagnostics/scans/tests return to their tool menu; use Back again for the main menu. Enter retains the default shown at each prompt. Ctrl+C on the idle main menu exits.

Setup reports prepared capabilities, not a successful tunnel: its CA applies to supported website HTTPS fronting in Balanced/Fast; Windscribe prohibits foreign exits. Certificate and exit setup stay open after an action so the result can be reviewed before returning.

WARP's initial registration API can be blocked even when its MASQUE/WireGuard gateways are reachable. Setup prepares separate `masque.toml` and `wg.toml` identities in the per-user `ktest/warp` configuration directory. It reuses locally valid identities without calling registration. Missing identities are registered through an available local proxy, explicit DNS-free ECH, Aether's Psiphon CDN carrier, then fragmented API HTTPS. The Psiphon carrier here carries registration only. These alternatives are attempts, not a guarantee against an ISP's filtering. See the [pinned Aether documentation](https://github.com/CluvexStudio/Aether/blob/v2.3.0/Docs/DOCS.en.md).

Registration writes into a temporary directory, validates the result offline, and publishes it without replacing an existing identity. Failure or cancellation keeps saved keys. Damaged/expired identities require an explicit repair/removal; do not delete working keys just because the network is offline. `YES` in Setup retries missing primary identities. `REMOVE` deletes the five explicitly named primary/nested WARP identity files, keeping settings, measurements and cores. During a connection, Aether workers serialize initial registration and attempt it at most once per missing identity; repeated tunnel searches do not repeatedly create WARP devices. Nested identities are prepared lazily; Gool registers its inner WireGuard identity through an outer MASQUE carrier. Psiphon profiles need no WARP identity. Runtime automatic reprovisioning is disabled; Aether may still contact the API for account checks or certificate renewal, so stored keys do not promise permanently API-free operation.

The CDN tool tests provider HTTPS by default. With your configured Windscribe CDN hostname, use ktest scan -windscribe-cdn your.hostname; that branch requires certificate-verified TLS and a valid WebSocket 101 for the hostname. Neither scan authenticates OpenVPN. The menu exposes Cloudflare/Akamai/Google/Fastly providers; own Windscribe CDN routing uses the Cloudflare branch.

Use ktest windscribe-test -target "Ashburn - Bles Park" for a fixed-node SNI comparison, or a requested OpenVPN TCP IP from the feed. Use ktest windscribe-test -verify-vpn once Windscribe is connected to compare one system HTTPS request against the CLI-reported exit. See WINDSCRIBE_BOOTSTRAP.md for stage meanings and limits.

## 9. What is, and is not, possible

* Local anti-DPI paths connect through your network. Foreign exits, Tor and fronted HTTP routes have different IP semantics; choose a policy explicitly. A pinned upstream is not a guarantee of a fixed public IP.
* Changing a byte of the ClientHello (rewriting the SNI, changing its case) is not possible for a transparent relay: the TLS handshake transcript would no longer match and the handshake fails. ktest cuts the ClientHello, it does not edit it.
* Fake packets with a low TTL need packet injection; they are available only through ByeDPI's own Windows implementation (the `fake` strategies).
* Application UDP and QUIC are not carried by ktest TUN. Aether's exempt helper may itself use outer HTTP/3/QUIC.
* Local packet manipulation cannot guarantee access to an IP-blocked destination; a working exit carrier may reach it.
* No result in this repository comes from a measured Iranian ISP. `Diagnose` and the result box tell you what happens on **your** network, right now.

## 10. Where ktest looks for its files

`cores/` and `profiles/` are searched next to the executable, then in the working directory, `./dist/ktest-portable` and `./ktest-portable`. `KTEST_BASE` or `-base DIR` overrides it. `ktest strategies -write` creates the editable `profiles/byedpi-strategies.txt` (the packaged build ships it).

## 11. Output

Colors, box drawing and the in-place progress line are used only on an interactive terminal. In a pipe, a file, CI, with `NO_COLOR` or `TERM=dumb`, output is plain ASCII. Set `KTEST_ASCII=1` to force ASCII on a terminal that cannot show the glyphs.

The menu uses aligned columns in wider windows and puts descriptions below each choice in narrower windows. Panels, status messages, and prompts wrap to the current terminal width; redirected output uses 80 columns. Connection events show the exact hostname (and nonstandard port), outcome, setup time, and selected route. TLS setup times include waiting for fallback waves; one second or more is highlighted as slow. Repeated successes on the same destination/route and speed class are counted without repeating the line, and repeated failures are shown at most once every 20 seconds per destination. Long errors are shortened in normal output; `-v` preserves their full context.

`TCP OPEN` reports proxy TCP establishment only, including raw non-TLS traffic previously absent from the live feed. `OPENVPN REPLY` reports an OpenVPN control-frame response on a Windscribe carrier; authentication and usable VPN data are still unverified. `TLS RESPONSE` reports a complete ServerHello; `ROUTE READY` means a fronting takeover is prepared but the application has not yet accepted its TLS connection. Neither proves an entire page or application works. `EARLY CLOSE` reports post-hello quality feedback without counting a second request. The session summary separates initial responses, prepared fronting routes, application refusals, TCP-only requests, and early closes. Route selection counts use live events from this session, retain ended exits, and exclude startup probes; average/maximum setup times and the number of slow setups are shown. If events are omitted under load, the summary marks its counts as partial.

## Options of `ktest connect`

None are needed. For experiments: `-v` (log every path decision and core output), `-listen`, `-strategies N`, `-no-xray`, `-no-self`, `-no-direct`, `-no-front`, `-front`, `-no-warp`, `-aether-method`, `-tun`, `-cert`, `-no-doh`, `-stagger`, `-first-byte`, `-ready`, `-base`. Windscribe mode: `-windscribe-wstunnel`, `-windscribe-wstunnel-sni`, `-windscribe-wstunnel-ip`, `-windscribe-cdn`, `-windscribe-cdn-sni`, `-windscribe-cdn-edge`, `-windscribe-auto-reconnect`, `-windscribe-cli` (see [WINDSCRIBE_BOOTSTRAP.md](WINDSCRIBE_BOOTSTRAP.md)).
