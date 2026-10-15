# CLI initial connectivity profile (2026-10-15)

This module uses the **existing** public Patterniha v52 serverless profiles to try to restore direct access to selected foreign HTTP(S) destinations. It is not a VPN and does not promise general foreign IP access.

Source: https://github.com/patterniha/Serverless-for-Iran
Official Xray: https://github.com/XTLS/Xray-core/releases

## Prepare once, while downloads are reachable

1. Obtain the latest official Xray executable for the operating system, plus the matching \`geoip.dat\` and \`geosite.dat\` assets. This control program and Xray remain separate native binaries. Xray must be >= 26.6.27.
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

- Uses upstream Fragment A/B implementation, not our own undocumented DPI attack. Fragment B was reported to work for some sites and networks in September–October 2026; also failed for other users and services. It cannot restore an IP route deleted by ISP allowlisting.
- Ahmad-2213 described timed TCP fragmentation on Simin/Frough datacenters, notably differing behavior across the two. His statements explicitly caution against generalizing to mobile, home ISPs or Android. See https://github.com/patterniha/Serverless-for-Iran/issues/28 and https://github.com/XTLS/Xray-core/discussions/4658
- ByeDPI https://github.com/hufrea/byedpi is a cross-platform local SOCKS proxy with documented DPI desync methods. It may be a fallback when Xray does not work, but not a transparent system-wide fix.
- Zapret2 https://github.com/bol-van/zapret2 has packet-level tools for TCP/UDP and Windows/Linux/OpenWrt, but does not support macOS; typically requires privileged OS hooks and its own system-specific setup.
- **No real Iranian ISP connectivity result was obtained in this repository.** A successful local boot only proves that the config parsed and a proxy started.
- The public repository must not receive personal traffic logs, connection details or credentials.
