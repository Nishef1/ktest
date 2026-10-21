# Direct-access integration — 2026-10-13

> **Current status (2026-10-21):** the narrow external-engine integration remains a separate, opt-in path. The local-test status below is not a current Iranian-ISP success claim and does not replace the main mode policies. See [current audit](CURRENT_AUDIT_2026-10-21.md) for the latest source/CI boundary.

Status: **local integration tests passed; NOT verified on an Iranian ISP.**
This is a domain-scoped HTTPS CONNECT adapter, not a full VPN. It uses the existing SNI-Spoofing-Go packet-injection engine, without building a new injection implementation or installing any root CA.

## Evidence behind this implementation

- SNI-Spoofing-Go v0.7.2 (official CLI release dated 2026-06-01): https://github.com/aleskxyz/SNI-Spoofing-Go/releases/tag/v0.7.2 . It supports local forwarding, fake ClientHello injection, Firefox/Chrome/etc uTLS fingerprints, active/passive injector modes, and optional real ClientHello fragmentation.
- A user in https://github.com/patterniha/SNI-Spoofing/issues/24 reported a working loopback SNI bridge and decoy/edge combinations in April–May 2026. This is a *dated user report*, not verified October availability.
- MITM-DomainFronting v23 has an unresolved August 2026 failure report: https://github.com/patterniha/MITM-DomainFronting/issues/191 . It also requires local TLS interception; we deliberately avoid silently installing trusted root certificates.
- This project does not bundle, download or silently elevate the third-party CLI. We use pinned SHA256 digests from the official v0.7.2 GitHub release metadata and verify the binary before launching it.

## Use

Download the official **CLI**, not GUI, for your OS from the v0.7.2 release. Run with the privileges required by the upstream injector (Windows Administrator or Linux elevated network privileges):

\`\`\`sh
ktest access -domain YOUR_DOMAIN -engine ./sni-spoofing-linux-amd64 -connect YOUR_EDGE_IP:443 -fake-sni YOUR_DECOY_HOST -utls firefox
\`\`\`

On Windows use \`sni-spoofing-windows-amd64.exe\`. Choose a destination IP actually serving the selected HTTPS domain and a decoy matching a documented method; May 2026 examples are not a promise of current reachability.

Configure the browser or an application explicitly to use the **HTTP proxy** at \`127.0.0.1:1089\`. HTTPS uses CONNECT. Only the listed \`-domain\` can traverse that proxy; all other hosts and non-443 ports are refused. The site TLS session remains end-to-end and is still verified by the browser. Public egress IP stays unchanged if the connection succeeds.

If the upstream SNI injector is already running on \`127.0.0.1:40443\`, omit engine launch entirely:

\`\`\`sh
ktest access -domain YOUR_DOMAIN -bridge 127.0.0.1:40443
\`\`\`

Ctrl+C stops ktest and requests graceful shutdown of an engine child started by ktest. The app does not change OS proxy, DNS, firewall or routing settings. The third-party packet injector may modify its own packet hooks while running, according to its upstream code.

## Why narrow defaults

- The proxy binds to localhost and denies unmatched domains, rather than silently leaking traffic outside the bypass.
- \`-enable-fragment\` defaults off, as upstream does; do not assume splitting more packets improves success.
- The engine is started as a subprocess, not copied or linked into this code. CLI arguments are built explicitly, no shell interpolation.
- The pinned upstream checksums are in \`internal/access/engine.go\`. A newer/rebuilt binary requires an **explicit, independently verified** \`-engine-sha256\` value.
- One chosen edge will not necessarily serve multiple unrelated domains. Certificate, CDN host-routing and source-IP filtering restrictions still apply.
- QUIC/UDP and browser features that ignore HTTP CONNECT are out of scope.
- No Iranian-ISP results or sensitive connection details belong in this public GitHub repository.
