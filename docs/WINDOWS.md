# Windows portable use (2026-10-15)

Download **ktest-windows-portable** from the newest successful **windows-portable** GitHub Actions run, not the older **ktest-windows-amd64** artifact under **verify**. The portable artifact contains one ZIP with the full folder below. Artifact downloads may require GitHub sign-in. No admin access or installer is required to start the loopback-only proxy.

```
ktest/
  ktest.exe
  cores/
    xray.exe
    ciadpi.exe
    geoip.dat
    geosite.dat
  profiles/
    Serverless-for-Iran.json
  THIRD_PARTY/
    Xray-MPL-2.0.txt
    ByeDPI-MIT.txt
    Serverless-GPL-3.0.txt
    NOTICES.md
```

1. Extract the ZIP fully to a directory such as `C:\ktest\`. Do not run `ktest.exe` directly from the compressed folder; it locates `cores` and `profiles` beside itself.
2. Open PowerShell in that directory, then `.\ktest.exe`. The menu requires only a single number, Enter.
3. First try **1 Direct access (Fragment B)**. If it fails for a site, return to the menu and try **2 Fragment A**. These profiles are selective; do not assume all services or protocols will work.
4. The program prints the local address `127.0.0.1:10808`. Configure a browser or app to explicitly use this local **SOCKS5** proxy (Firefox: Settings > General > Network Settings > Settings > Manual proxy configuration > SOCKS Host `127.0.0.1`, Port `10808`, SOCKS v5, optionally proxy DNS through SOCKS). Core must remain running while browsing.
5. For **3 Adaptive DPI** or **4 TLS record slicing**, choose SOCKS5 `127.0.0.1:10809` instead. This is ByeDPI, not Xray. Run only one selection at a time.
6. **5 Find CDN IP candidates** checks only a handful of Akamai/Fastly/Google addresses. It is diagnostic, not an automatic connection method.
7. Ctrl+C stops the active child; option 0 exits. If the console is closed, the proxy stops. Reset browser proxy to No proxy / Use system settings afterward.

The CLI does NOT automatically enable a Windows system proxy, set DNS or install certificates. It does NOT make the user's separately installed VPN/WireGuard use this SOCKS proxy. A successful browser test does not prove that Windscribe can connect. There is not yet an operational MITM mode; no CA is silently installed.

The portable archive is built by GitHub Actions from pinned official Xray v26.10.10 and ByeDPI v0.17.3 release archives (SHA-256 checked), plus an upstream version-pinned, Git-blob-verified v52 Serverless-for-Iran JSON profile. All license texts and attributions are included. A Windows SmartScreen warning for an unsigned binary can occur; verify source and SHA-256 before deciding whether to run it.

**Status:** CI tests verify binary startup and menu behavior, not in-Iran bypass effectiveness. If Windows packaging fails, there is no completed self-contained downloadable artifact; inspect the workflow logs rather than claiming success.
