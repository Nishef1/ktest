# Verified upstream versions — reviewed 2026-10-21

Official release pages were checked before selection. This repository does not bundle external executables.

| Component | Version checked | Published | Use in ktest | Official source |
| --- | --- | --- | --- | --- |
| Aether | **v2.3.5** | 2026-10-23 | Pinned runtime on Windows/Android; protocol CLI matches v2.3.1; Android verifies archive and extracted executable hashes | https://github.com/patterniha/Aether/releases/tag/v2.3.2 |
| Xray-core | **v26.10.21** | 2026-10-21 | Pinned official Windows executable and Android ARM64 `libxray.so`; local TLS-fragment route and Android TUN adapter | https://github.com/XTLS/Xray-core/releases/tag/v26.10.21 |
| HEV | **2.19.0** | Pinned | Android TUN fallback; app minimum API 29 follows the upstream manifest | https://github.com/heiher/hev-socks5-tunnel |
| ByeDPI | **v0.17.3** | Pinned | Hash-pinned Android ARM/ARM64 local anti-DPI helper; candidate strategies are not proven for every ISP | https://github.com/hufrea/byedpi/releases/tag/v0.17.3 |
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
