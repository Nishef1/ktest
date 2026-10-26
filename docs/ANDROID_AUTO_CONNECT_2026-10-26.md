# Automatic Android connection — preview 0.5.4

- User-selected mode, DNS, method, TLS fingerprint, SNI and fragment values remain authoritative. Empty or Auto values use the built-in adaptive policy.
- Trusted encrypted DNS uses the existing DoH fallback inventory; strict Aether/Psiphon/Tor modes never send system DNS outside their verified exit.
- Aether Auto/H2 measures SNI, fingerprint and fragment ranges with an 8-second budget if network cache is stale. Successful calibrations are cached for 6 hours; negative results are cached for 10 minutes. A failed test never disables ordinary profiles.
- On independent Psiphon CDN Auto or Balanced/Fast with explicitly consented fronting, inspect up to 12 Cloudflare and 12 Fastly IPs (5-second shared budget) and cache only provider-HTTPS-verified results per underlying network. Failure is rate-limited 15 minutes. This does not verify target fronting.
- Existing routing continues per-site active learning and honors recent verified profile seeds. No arbitrary certificate trust, universal ISP connectivity, or promise that a responsive CDN IP is a working proxy.
- Android proxy endpoints stay at 127.0.0.1:10808 SOCKS5 and 127.0.0.1:10809 HTTP unless user changes both in Settings while disconnected. A port collision is reported rather than silently switching.
- The top Before/Exit IP and flag rows reserve constant height. Core warnings and advanced diagnostics remain in their relevant panels rather than pushing Exit IP down.

QA: Go, Windows, Android JNI/APK and physical Android 10 testing. The first connection on a new network may perform bounded tests; comprehensive scans remain under Tools and do not block every Connect.
