# ktest

## Setup

### Windows portable

1. Open the latest successful `windows-portable` GitHub Actions workflow run.
2. Download the `ktest-windows-portable` artifact.
3. Extract both ZIP layers completely.
4. Open Windows Terminal in the extracted `ktest` directory.
5. Run:

```powershell
.\ktest.exe
```

### From source

Install the Go toolchain, open a terminal in the repository, and run:

```powershell
go run ./cmd/ktest
```

For a local executable:

```powershell
go build -o ktest.exe ./cmd/ktest
.\ktest.exe
```

## Current verification status (2026-10-21)

The latest reviewed source snapshot is [`978e0ab`](https://github.com/Nishef1/ktest/commit/978e0ab487e086ed5da61478f313db60bf272365). Its then-current CI passed Go tests/race/formatting, Android source checks, the Android APK build and the Windows portable package. These checks do **not** establish physical-phone reliability, current ISP reachability, end-to-end service access, or CPU/RAM/battery efficiency. See the [current audit and open issues](docs/CURRENT_AUDIT_2026-10-21.md).

## Documentation

- [Usage](docs/USAGE.md)
- [Windows setup](docs/WINDOWS.md)
- [Connection modes](docs/CONNECTION_MODES.md)
- [Aether methods and network diagnosis](docs/NETWORK_DIAGNOSIS.md)
- [Windscribe bootstrap](docs/WINDSCRIBE_BOOTSTRAP.md)
- [Zapret2 Windows packet experiment](docs/ZAPRET2_WINDOWS_INTEGRATION.md)
- [Direct access](docs/ACCESS.md)
- [Domain fronting](docs/FRONTING.md)
- [Experiments](docs/EXPERIMENTS.md)
- [Revive](docs/REVIVE.md)
- [Upstream versions](docs/UPSTREAM.md)
- [Third-party notices](docs/THIRD_PARTY_NOTICES.md)
- [IP sources](docs/IP_SOURCES.md)
- [Research](docs/RESEARCH.md)
- [Roadmap](docs/ROADMAP.md)
- [Current source, CI, performance and known-issue audit](docs/CURRENT_AUDIT_2026-10-21.md)
