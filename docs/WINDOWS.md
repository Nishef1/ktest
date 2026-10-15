# Windows portable — managed CLI (2026-10-15)

Use the latest successful `windows-portable` GitHub Actions artifact `ktest-windows-portable`; extract both ZIP layers fully. The complete folder includes `ktest.exe`, `cores/xray.exe`, `cores/ciadpi.exe`, `cores/sing-box.exe`, `cores/wintun.dll`, `profiles/Serverless-for-Iran.json`, and third-party license texts. Do not run just the executable extracted from the generic `verify` workflow.

Open Windows Terminal inside the extracted `ktest` directory and enter `.\ktest.exe`. Select using a single number and Enter.

- **1** Direct Xray Frag B; **2** Direct Xray Frag A; **3** ByeDPI adaptive; **4** ByeDPI TLS slicing. Selecting another mode stops the previous core first. The menu stays responsive while the core runs.
- After the local SOCKS listener comes up the app *automatically* attempts real TLS-verified HTTP 204 checks through the same SOCKS proxy for YouTube and Google. A `PASS` is limited to that target. A `FAIL` means bypass has **not** been confirmed, even if Xray reports `started`.
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
