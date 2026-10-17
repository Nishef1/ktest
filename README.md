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

## Documentation

- [Usage](docs/USAGE.md)
- [Windows setup](docs/WINDOWS.md)
- [Connection modes](docs/CONNECTION_MODES.md)
- [Aether methods and network diagnosis](docs/NETWORK_DIAGNOSIS.md)
- [Windscribe bootstrap](docs/WINDSCRIBE_BOOTSTRAP.md)
- [Direct access](docs/ACCESS.md)
- [Domain fronting](docs/FRONTING.md)
- [Experiments](docs/EXPERIMENTS.md)
- [Revive](docs/REVIVE.md)
- [Upstream versions](docs/UPSTREAM.md)
- [Third-party notices](docs/THIRD_PARTY_NOTICES.md)
- [IP sources](docs/IP_SOURCES.md)
- [Research](docs/RESEARCH.md)
- [Roadmap](docs/ROADMAP.md)
