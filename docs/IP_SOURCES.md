# CDN IP Source Review — 2026-10-15

Purpose: prefer proven upstream logic without copying unsafe TLS behavior. Internet reachability from a particular Iranian ISP is not established by GitHub README claims.

## Sources and decisions

* Se7en-Pro (MIT; last pushed 2026-10-05): source-backed Akamai seed IPs and SNI-aware Dial Override configuration. Eight candidate addresses are retained in the ktest catalog, explicitly unverified. Source: https://github.com/KNG7-P/Se7en-Pro/blob/master/Se7enPro/Services/CdnFrontingBuilder.cs . Psiphon needs valid embedded network values; its Windows GUI is not portable.
* MahsaNG v18 (2026-10-02; GPL-3.0): scanner extends beyond HTTPS to MASQUE, WireGuard and customizable ports. Design lesson: TLS accessibility is not proof of UDP or VPN connectivity. https://github.com/GFW-knocker/MahsaNG/releases
* ShirOKhorshid: Psiphon CDN fronting and scanner; user reports of CDN failure within hours, suggesting small per-ISP verification instead of permanent clean IP lists. https://github.com/shirokhorshid/shirokhorshid-android/issues/28
* hossein8360/cdn-ip-finder: static CDN seed groups and browser no-cors reachability test. Its browser timing/error test cannot reliably distinguish blocked TCP, TLS certificate rejection and browser policy. Source last pushed 2026-05-18. https://github.com/hossein8360/cdn-ip-finder
* MidONe: CDN header identification, retries, latency, and bandwidth estimates. Critically, code turns OFF TLS certificate validation (check_hostname=False; verify_mode=CERT_NONE): do NOT copy the scanner or use its claims as verified fronting. Last pushed 2026-05-21. https://github.com/mwhammadrezss/ShiroKhorshidScanner/blob/main/MidONeScanner.py
* iran-proxy-checker: research source for SNI/fronting candidate records, but its principal measurement direction is from overseas *into* Iranian infrastructure, opposite to the local outbound requirement. https://github.com/mmbateni/iran-proxy-checker

## Implemented

Menu item 5 and CLI command: ktest scan -provider akamai|fastly|google.

Akamai: eight unverified static seed IPs from the Se7en-Pro source. Fastly and Google: up to eight DNS candidates from pypi.org or fonts.googleapis.com, subject to possible DNS poisoning.

One bounded HTTPS request per candidate with certificate verification. This reports TLS response and HTTP status, not validated CDN fronting or a working proxy. A controlled origin nonce is still required to prove desired CDN routing; generic success-looking HTTP is labelled unverified. No wide CIDR scanning, admin permissions or system routing changes.

## Next practical gate

Integrating a specific fronting route requires a provider-compatible edge, legitimate fronted origin / Psiphon server entry, and verified TLS. Never assume arbitrary Host/SNI mismatches are accepted. No in-Iran field success is claimed.