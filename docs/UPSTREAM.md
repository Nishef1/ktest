# Verified upstream versions — 2026-10-13

Official release pages were checked before selection. This repository does not bundle external executables.

| Component | Version checked | Published | Use in ktest | Official source |
| --- | --- | --- | --- | --- |
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
- Success in a local harness does not establish that any Iranian operator can reach an overseas target today.
