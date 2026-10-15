# Third-party notices and offline-core provenance

The portable Windows package bundles unmodified third-party executables and one publicly distributed configuration, as separate files. No fork is created.

- **Xray-core v26.10.10** (XTLS), https://github.com/XTLS/Xray-core — MPL-2.0. The official Windows asset is SHA-256 pinned. Full license is included in THIRD_PARTY/Xray-MPL-2.0.txt.
- **ByeDPI v0.17.3** (hufrea), https://github.com/hufrea/byedpi — MIT. The official Windows asset is SHA-256 pinned. Full license is included in THIRD_PARTY/ByeDPI-MIT.txt.
- **Serverless-for-Iran v52** (@patterniha), https://github.com/patterniha/Serverless-for-Iran — GPL-3.0. Exact JSON profile is pinned by upstream commit 19e394313afd347ca0935bea0def25522434dbe6 and blob ab1dd41508e073df841dfa781969550bbdd20927. Full license is included in THIRD_PARTY/Serverless-GPL-3.0.txt.

The ktest menu and scanner are an independent Go orchestration project. The package never installs third-party trusted root certificates, rewrites OS proxy/DNS settings, or promises that an arbitrary site will be reachable on an Iranian ISP. Redistributors must preserve applicable licenses and attributions.

- **sing-box v1.14.3** (SagerNet), https://github.com/SagerNet/sing-box — GPL-3.0-or-later. The official Windows amd64 archive is SHA-256 pinned; the full license is included in THIRD_PARTY/sing-box-GPL-3.0.txt. Used only for opt-in system-wide Windows TUN.
- **Wintun v0.14.1** (WireGuard LLC), https://www.wintun.net/ — signed upstream prebuilt DLL with redistribution terms from the official archive (THIRD_PARTY/Wintun-LICENSE.txt); archive SHA-256 pinned. The developer prebuilt license differs from the Wintun source-code GPL-2.0 terms.

TUN may temporarily change system routes or DNS behavior. Windows requires Administrator approval; it is never silently enabled. An unexpected crash may require manual network adapter recovery.
