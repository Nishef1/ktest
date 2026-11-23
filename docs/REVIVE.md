# Serverless-for-Iran: optional offline local proxy (updated 2026-11-23)

> **Historical recipe:** this file captures an experimental CLI setup, not the canonical current mode contract. The latest source has no AI/TikTok-specific route rule; WARP carrier readiness is not proof of a foreign IP or a working application data plane. Check [USAGE.md](USAGE.md), [CONNECTION_MODES.md](CONNECTION_MODES.md) and [CURRENT_AUDIT_2026-10-21.md](CURRENT_AUDIT_2026-10-21.md) before relying on any old result.

This module uses the **pinned** public Patterniha v65 Serverless profiles (A/B/OOB) to try to restore direct access to selected foreign HTTP(S) destinations. It is not a VPN and does not promise general foreign IP access.

Source: https://github.com/patterniha/Serverless-for-Iran
Official Xray: https://github.com/XTLS/Xray-core/releases

## Prepare once, while downloads are reachable

1. Obtain the latest official Xray executable for the operating system, plus the matching \`geoip.dat\` and \`geosite.dat\` assets. This control program and Xray remain separate native binaries. The current v65 subscription requires patterniha/Xray-core >= 26.11.23; its minimum is checked before launch.
2. Save the upstream plain JSON subscription file locally as \`Serverless-for-Iran.json\`:
   https://raw.githubusercontent.com/patterniha/Serverless-for-Iran/refs/heads/main/Subscription/Serverless-for-Iran.json
3. Keep both locally for offline relaunch; \`ktest revive\` does **not** fetch or update the profile at startup.

## Run (same CLI across OSes)

\`\`\`sh
ktest revive -xray ./xray -profile ./Serverless-for-Iran.json -variant B -assets ./assets
\`\`\`

On Windows, use \`-xray .\\xray.exe\`. On Linux/macOS, make sure the file is executable.

\`ktest revive\` selects one upstream profile, forces the only inbound to \`127.0.0.1:10808\`, writes a temporary local config, runs \`xray version\` and \`xray run -test -c\`, then runs Xray until Ctrl+C. It does not change global DNS, proxy, TUN, trusted certificates, routing or firewall.

For a command-line application that explicitly supports HTTP proxies, use \`http://127.0.0.1:10808\`. For applications supporting SOCKS5, use \`127.0.0.1:10808\`. Verify an application actually uses this proxy; otherwise its traffic stays unchanged.

**Do not assume Windscribe will connect just because this proxy works.** WireGuard makes its own UDP flows and is not automatically routed through the proxy; Windscribe Proxy Gateway works in the other direction (VPN -> local proxy). In Windscribe, separately try its native \`Circumvent Censorship\` / AmneziaWG, Stealth or WStunnel options where supported.

## Scope and evidence

- Uses upstream Fragment A/B and OOB implementation, not our own undocumented DPI attack. Fragment B was reported to work for some sites and networks in September–October 2026; also failed for other users and services. It cannot restore an IP route deleted by ISP allowlisting.
- Ahmad-2213 described timed TCP fragmentation on Simin/Frough datacenters, notably differing behavior across the two. His statements explicitly caution against generalizing to mobile, home ISPs or Android. See https://github.com/patterniha/Serverless-for-Iran/issues/28 and https://github.com/XTLS/Xray-core/discussions/4658
- ByeDPI https://github.com/hufrea/byedpi is a cross-platform local SOCKS proxy with documented DPI desync methods. It may be a fallback when Xray does not work, but not a transparent system-wide fix.
- Zapret2 https://github.com/bol-van/zapret2 has packet-level tools for TCP/UDP and Windows/Linux/OpenWrt, but does not support macOS; typically requires privileged OS hooks and its own system-specific setup.
- **No real Iranian ISP connectivity result was obtained in this repository.** A successful local boot only proves that the config parsed and a proxy started.
- The public repository must not receive personal traffic logs, connection details or credentials.

## Bundled Windows portable package

With the official KTest portable ZIP, run `ktest.exe revive -variant B` (or `A` / `OOB`)
from any directory. KTest resolves the pinned `cores/xray.exe`, the pinned
`profiles/Serverless-for-Iran.json`, and `cores/geoip.dat` / `cores/geosite.dat`
relative to its own executable. The command starts a **separate** local proxy;
it does not install a system VPN or replace the normal adaptive routing session.
On Android, the user can explicitly select a separate **Serverless** mode and
Fragment A, Fragment B or OOB in the Connection method selector. It runs the
pinned upstream v65 profile using the packaged Xray and verified GeoIP/GeoSite
assets, publishes only a local SOCKS/HTTP proxy, and never grants a foreign
exit or silently activates Android's VPN. The existing Xray fragmentation
route and Xray-TUN/HEV packet adapter remain in the normal modes.
