# Windows portable — managed CLI (2026-10-15)

Use the latest successful `windows-portable` GitHub Actions artifact `ktest-windows-portable`; extract both ZIP layers fully. The complete folder includes `ktest.exe`, `cores/xray.exe`, `cores/ciadpi.exe`, `cores/sing-box.exe`, `cores/wintun.dll`, `profiles/Serverless-for-Iran.json`, and third-party license texts. Do not run just the executable extracted from the generic `verify` workflow.

Open Windows Terminal inside the extracted `ktest` directory and enter `.\ktest.exe`. Select using a single number and Enter.

- **1** Direct Xray Frag B; **2** Direct Xray Frag A; **3** ByeDPI adaptive; **4** ByeDPI TLS slicing. Selecting another mode stops the previous core first. The menu stays responsive while the core runs.
- After SOCKS starts the app checks **YouTube and Google through SOCKS and directly without ktest in parallel**, with validated HTTPS. A connected Windscribe or other VPN can carry both requests: in that case success is **NOT** attributed to ktest. The app detects known active VPN interfaces and a running Windscribe client on Windows, and conservatively labels results UNVERIFIED when present. A `CANDIDATE` requires proxy success, direct failure, and no detected VPN; it is not definitive proof of overcoming filtering.
- **5** displays source-attributed CDN IP candidate checks. An IP reaching TCP but failing TLS is not proven blocked by the DPI, nor is it a working fronting route.
- **6** toggles *experimental system-wide TCP TUN* on Windows via official sing-box 1.14.3 + signed Wintun 0.14.1. The option is disabled unless a current proxy has at least one verified HTTP result. Must run Windows Terminal **as Administrator**. TUN changes Windows routes; explicit `YES` is required; TUN is stopped automatically if direct website checks fail. Only TCP is forwarded through the local SOCKS; UDP other than DNS is blocked. This is not a complete UDP VPN or a guaranteed way to connect Windscribe.
- **7** stops the selected core (and any TUN) without closing the menu. **8** retests the targets through the current SOCKS proxy. **0** stops everything and exits. Ctrl+C is intercepted to request stop rather than immediately terminating the launcher. If the TUN process is forcibly killed or the machine crashes, inspect network adapters/routes and restart Windows if connectivity does not recover.

This tool does **not** silently change global proxy settings. Without TUN, explicitly set application SOCKS5 to `127.0.0.1:10808` for Xray or `127.0.0.1:10809` for ByeDPI. In Firefox, set `Settings > General > Network Settings > Manual proxy`; enable proxy DNS over SOCKS5. The proxy is not an external VPN, and the public IP may stay Iranian.

**Operational limitations**:
- No live Iranian ISP measurements have been made in CI. Both automatic checks may fail in filtered networks even when the program launches correctly.
- Windows TUN is a *beta* integration, not an independently field-validated setup. It selects an apparent physical NIC and uses process-based physical-bypass rules; do not combine with another VPN while trialing it. Upstream sing-box issues documented DNS/TUN packet loops on Windows, hence the guard for TUN CIDRs. Some device adapters or enterprise firewalls may reject route modifications.
- A regular TCP/IP proxy cannot make a separate UDP WireGuard transport work. Global TUN in this stage intentionally rejects most UDP; it is not appropriate for gaming, WireGuard/QUIC, or reliable all-protocol VPN.
- The Xray/ByeDPI settings are derived from public projects and may be stale for any specific ISP. `PASS` only confirms successful HTTP transport for the tested host, not all of YouTube's media domains.
- All additional binaries are downloaded on GitHub Actions from upstream versioned assets and SHA-256 verified. Redistribute license notices with the executable files.


## VPN-confounded measurements (2026-10-15)

A user report showed **2/2** Google/YouTube through the local SOCKS while Windscribe was connected, followed by **0/2** when it was disconnected. Those first 204 responses did **not** verify our technique. The Xray second pass failed with \`cloudflare-dns.com/dns-query\` timeouts; that is compatible with an inaccessible DNS bootstrap route but does not uniquely establish DPI interference. ByeDPI Google 204 alone is insufficient to demonstrate YouTube or all-system access.

Current terminal logic reports:
- \`BASELINE\`: ordinary connection without ktest also succeeded, so no benefit attributed.
- \`UNVERIFIED\`: Windows detected possible VPN usage, including a running Windscribe client even with split tunneling.
- \`CANDIDATE\`: the chosen proxy reached a target and the direct control failed with no other VPN detected. Not a proof of ISP DPI mechanism or full access.
- \`FAIL\`: the target did not return the expected HTTPS 204 through the proxy.

Before attempting the comparison, disconnect Windscribe and close its desktop client. Its firewall may remain enabled with Manual/Always On settings, in which case direct traffic can stay blocked even after disconnecting. Do not let the CLI disable any firewall or privacy protection silently. The user must make any firewall change knowingly. Source: https://windscribe.com/knowledge-base/articles/firewall-modes

CDN IP checks are refused when a VPN is detected or suspected: a reachable Akamai edge via Windscribe is not automatically reachable from the user's ISP. Network heuristics cannot perfectly detect every VPN (particularly per-app split tunneling), so all positive results remain cautious. The CLI does not read or reveal the user's external IP or upload their results.
