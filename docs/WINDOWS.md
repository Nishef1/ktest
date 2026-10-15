# Windows portable — managed CLI (2026-10-15)

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
