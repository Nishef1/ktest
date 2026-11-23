# Verified upstream versions — updated 2026-11-23

Official release pages and pinned SHA-256 digests were checked before selection. The Windows portable ZIP and Android APK package selected verified third-party binaries; the repository tracks their manifests and provenance.

| Component | Version checked | Published | Use in ktest | Official source |
| --- | --- | --- | --- | --- |
| Aether | **v2.4.0** | 2026-10-24 | Reviewed update for Android/Desktop: WARP API edge fallback, H2/TLS and reconnect fixes; signed APK and real-network acceptance still required | https://github.com/patterniha/Aether/releases/tag/v2.4.0 |
| Xray-core (PattNG fork) | **v26.11.23** | 2026-11-23 | Official Windows and Android ARM64 SHA-256 pinned; Android ELF digest derived from verified ZIP before Go JNI build | https://github.com/patterniha/Xray-core/releases/tag/v26.11.23 |
| HEV | **2.20.0** | 2026-11-13 | Exact PattNG P74 submodule revision `75dbc1e`; smaller idle stack memory, UDP fallback and deadlock fixes; official AAR SHA-256 pinned | https://github.com/heiher/hev-socks5-tunnel/releases/tag/2.20.0 |
| ByeDPI | **v0.17.3** | Pinned | Hash-pinned Android ARM/ARM64 local anti-DPI helper; candidate strategies are not proven for every ISP | https://github.com/hufrea/byedpi/releases/tag/v0.17.3 |
| PattNG app | **2.4.0-P74** | 2026-11-23 | Reference-only upstream app; app UI/config is not copied to KTest | https://github.com/patterniha/PattNG/releases/tag/2.4.0-P74 |
| Serverless-for-Iran | **v65** | 2026-11-23 | Windows and Android standalone selectable A/B/OOB local proxy; direct ISP IP, not a foreign VPN exit and never an implicit route in other modes | https://github.com/patterniha/Serverless-for-Iran |
| Go | **1.27.2** | 2026-10-08 | Minimum toolchain updated; security fixes include TLS/HTTP | https://go.dev/doc/devel/release |
| actions/checkout | **v7.0.1** | 2026-07-20 | CI on maintained `@v7` major | https://github.com/actions/checkout/releases |
| actions/setup-go | **v7.0.0** | 2026-07-16 | CI on maintained `@v7` major | https://github.com/actions/setup-go/releases |
| Zapret2 | **v1.0.5.2** | 2026-09-15 | Reference only; `nfqws2` profile-matching optimization | https://github.com/bol-van/zapret2/releases |
| SNI-Spoofing-Go | **v0.7.2** | 2026-06-01 | Reference only; active fake ClientHello approach | https://github.com/aleskxyz/SNI-Spoofing-Go/releases |

## Integration gates

- Revalidate tags and changelogs before any future binary integration; verify official checksums/signatures and inspect elevated software before execution.
- SNI-Spoofing-Go is GPL-3.0: review licensing before copying/linking code.
- `ktest compare -connect 127.0.0.1:PORT` can compare a direct route against a separately reviewed and running TCP forwarder. This project neither injects packets nor elevates privileges.
- Github Actions `@v7` major tags will track compatible patch updates; they are not immutable SHA pins.
- Success in a local harness or green CI does not establish that any Iranian operator can reach an overseas target today, or that the app is fast/efficient on a physical phone.
- Current code snapshot and CI boundaries are tracked in [CURRENT_AUDIT_2026-10-21.md](CURRENT_AUDIT_2026-10-21.md).

- 2026-10-13: GitHub Actions `actions/upload-artifact@v7` selected; v7.0.2 released 2026-10-07. Binaries uploaded as ephemeral Actions artifacts (not a GitHub release): https://github.com/actions/upload-artifact/releases
