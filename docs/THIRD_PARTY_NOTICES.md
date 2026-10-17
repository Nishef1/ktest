# Third-party notices and offline-core provenance

The portable Windows package bundles unmodified third-party executables and one publicly distributed configuration, as separate files. No fork is created.

- **Xray-core v26.10.10** (XTLS), https://github.com/XTLS/Xray-core — MPL-2.0. The official Windows asset is SHA-256 pinned. Full license is included in THIRD_PARTY/Xray-MPL-2.0.txt.
- **ByeDPI v0.17.3** (hufrea), https://github.com/hufrea/byedpi — MIT. The official Windows asset is SHA-256 pinned. Full license is included in THIRD_PARTY/ByeDPI-MIT.txt.
- **Serverless-for-Iran v52** (@patterniha), https://github.com/patterniha/Serverless-for-Iran — GPL-3.0. Exact JSON profile is pinned by upstream commit 19e394313afd347ca0935bea0def25522434dbe6 and blob ab1dd41508e073df841dfa781969550bbdd20927. Full license is included in THIRD_PARTY/Serverless-GPL-3.0.txt.

The ktest menu and scanner are an independent Go orchestration project. The package never rewrites OS proxy/DNS settings or promises that an arbitrary site will be reachable on an Iranian ISP. It trusts no certificate by itself: `ktest ca -install` creates a name-constrained local CA and asks Windows, with Windows' own confirmation, to trust it for the current user. Redistributors must preserve applicable licenses and attributions.

- **sing-box v1.14.3** (SagerNet), https://github.com/SagerNet/sing-box — GPL-3.0-or-later. The official Windows amd64 archive is SHA-256 pinned; the full license is included in THIRD_PARTY/sing-box-GPL-3.0.txt. Used only for opt-in system-wide Windows TUN.
- **Wintun v0.14.1** (WireGuard LLC), https://www.wintun.net/ — signed upstream prebuilt DLL with redistribution terms from the official archive (THIRD_PARTY/Wintun-LICENSE.txt); archive SHA-256 pinned. The developer prebuilt license differs from the Wintun source-code GPL-2.0 terms.

- **Aether v2.3.0** (CluvexStudio), https://github.com/CluvexStudio/Aether — AGPL-3.0. A Rust WARP core (MASQUE over HTTP/2 and HTTP/3) run as a separate, unmodified process only when the user enables the WARP exit; the official Windows archive is SHA-256 pinned (0cc32dd2d7573f91d2e55d4f427bfe4c6f6252342494e1b410d61b12d1e4dc79) and the license text is in THIRD_PARTY/Aether-AGPL-3.0.txt. The corresponding source is at the URL above. Enabling it registers a free anonymous Cloudflare WARP identity on the user's PC; traffic that uses it leaves through Cloudflare.

- **psiphon-tunnel-core** (Psiphon Labs; bundled build from [CluvexStudio's fork](https://github.com/CluvexStudio/psiphon-tunnel-core), branch `shirokhorshid`, revision `83aa73b9b982e7421e00117f5b0c5aceb5dda452`, GPL-3.0) and **lyrebird** (Tor Project, https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird, BSD-style) are the unmodified helpers that ship in the `pt/` folder of the pinned Aether archive. They are extracted next to `aether.exe` only when the user enables the exit paths, and only Aether starts them. Psiphon's original upstream is https://github.com/Psiphon-Labs/psiphon-tunnel-core; no separate KTest Psiphon engine is used.

TUN may temporarily change system routes or DNS behavior. Windows requires Administrator approval; it is never silently enabled. An unexpected crash may require manual network adapter recovery.

## Android native preparation

Android uses the unmodified Android executables in the official Aether v2.3.0
release, not the Windows or generic Linux Aether binary. Archive and per-file
SHA-256 values are recorded in `internal/aether/android-cores.json`; the native
packaging script verifies both levels before copying any file into `jniLibs`.

The x86_64 Psiphon executable's Go build metadata identifies the source revision
`83aa73b9b982e7421e00117f5b0c5aceb5dda452`, with `vcs.modified=false`; Aether's
pinned build script uses the CluvexStudio/psiphon-tunnel-core fork's
`shirokhorshid` branch at that commit. The same release builds Aether with Tor
support through Arti; Lyrebird is its pluggable-transport helper, not a second
standalone Tor engine. KTest uses these through Aether instead of acquiring or
implementing parallel Tor/Psiphon cores.
The x86_64 Lyrebird metadata identifies revision
`fc105a03c0e0acc2479301c361c012ffed359c43`, also unmodified. The corresponding
sources and license notices must be preserved in Android distribution just as
for the desktop executables. No Android APK/AAR has been produced or distributed
by this native-preparation step.

- Aether source and build scripts: https://github.com/CluvexStudio/Aether/tree/v2.3.0
- Psiphon helper source: https://github.com/CluvexStudio/psiphon-tunnel-core/tree/83aa73b9b982e7421e00117f5b0c5aceb5dda452
- Lyrebird helper source: https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/tree/fc105a03c0e0acc2479301c361c012ffed359c43
