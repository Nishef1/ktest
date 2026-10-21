# WARP first-use bootstrap and identity persistence (2026-10-20)

> **Follow-up (2026-10-21):** the current source pins Aether v2.3.2 and includes optional MASQUE TLS-shape/F&F calibration. That calibration is bounded to 15 seconds on a missing/stale cache, measures gateway TLS response rather than a working tunnel, and can still run when `wireguard` is explicitly selected. The `fragment=off` setting also does not suppress exit-node `tlshello-0-len` variants. These are open code issues, not identity corruption; see [CURRENT_AUDIT_2026-10-21.md](CURRENT_AUDIT_2026-10-21.md).

This change addresses four *separate* conditions visible in Windows logs:
the default SOCKS listener is occupied, the managed Aether core may be
absent/old, WARP enrollment may have no direct route to its HTTPS API, and
a local listener may exist without verified Internet egress.

## Windows, Linux and macOS

- **First managed connection**: selecting Aether, Psiphon, Tor or
  Windscribe-through-Aether installs a verified, SHA-256-pinned Aether
  v2.3.1 release when the needed core/helper is missing. This requires
  reaching GitHub; if all download paths are filtered, an offline portable
  package or an independently working bootstrap remains necessary. It
  cannot conjure Internet from no reachable network service.
- **First WARP credential**: the managed Aether search registers a missing
  MASQUE or WireGuard identity through KTest's local Fast/ByeDPI/Xray
  anti-DPI SOCKS path where it exists, and independently through
  ECH/fragmented HTTPS/Psiphon CDN enrollment candidates. Registration
  uses a staged temporary identity and publishes it only after offline
  validation. It never replaces a valid saved identity automatically.
  A usable Psiphon *enrollment* carrier is not permission to substitute
  Psiphon for the requested WARP **exit**.
- **Where keys live**: normally the per-user configuration folder returned by
  `os.UserConfigDir()/ktest/warp`, rather than the portable KTest directory.
  On Windows this is generally under the user's AppData\Roaming. Removing
  `D:\Data\ktest` or changing portable binaries therefore does not remove
  already saved identities. An uninstaller or system cleanup may still remove
  AppData.
- **Portable encrypted backup**: `ktest warp -backup PATH` writes a new
  password-protected JSON file (scrypt + AES-256-GCM). A hidden terminal
  prompt asks for a minimum 12-character password twice. The destination
  must not exist already; no passwords appear in command-line arguments.
  `ktest warp -restore PATH` validates/decrypts and installs only missing
  identities; existing valid keys are not overwritten.
- **Occupied ports**: if stock `127.0.0.1:10800` is occupied, KTest chooses
  a free ephemeral loopback SOCKS port and prints it. The default HTTP
  `127.0.0.1:10801` may also move when occupied. It never terminates the
  owner of either port. Explicit non-default `-listen` or `-http-listen`
  addresses remain fixed and fail on conflicts. A third-party app or
  Windscribe configured to use a *fixed* proxy must be updated manually to
  the newly displayed address; auto-relocating KTest does **not**
  reconfigure that other app.

## Android

- Aether, Balanced and Fast now reuse one app-private `filesDir/aether`
  credential directory. Previous `filesDir/automatic-exits` identities
  are migrated only if they validate; existing valid destination keys
  always win. Old directories are not deleted automatically.
- Without an existing VPN, first native WARP registration is tried via a
  bounded Fast carrier, fragmented TLS and Psiphon CDN registration
  using the SHA-pinned packaged helper. If those paths are blocked, Aether
  may still try its own registration. None is guaranteed to connect
  through all ISP restrictions.
- Ordinary APK updates with the same Android package/signature preserve
  private files. **Uninstalling** or **clearing data** removes app-private
  identities. There is no reliable, invisible cross-uninstall
  persistence path for a private key on Android.
- To survive an uninstall, go to **Settings → WARP identity recovery**,
  enter a backup password (12+ chars), and select **Save encrypted WARP
  backup**. This uses Android's document picker to save **only encrypted
  bytes** outside the app's private directory. After reinstallation,
  select **Restore encrypted WARP backup** and enter the same password.
  Restore is disabled while connected. Never share the backup together
  with the password.
- The app does **not** upload private WARP keys or export them unencrypted.

## Limitations, tests and next acceptance step

- A successful SOCKS bind is not proof of WARP gateway access or a
  non-Iranian exit. Independently verify HTTPS through the chosen proxy
  and check the final IP, DNS/TUN and Windscribe data-plane behavior.
- An external VPN may make network diagnostics ambiguous; the
  direct-ISP comparison correctly refuses to claim that samples taken
  through someone else's VPN are uncloaked baseline results. Registration
  can still use a working system network without such a comparison.
- KTest does not forcibly close an existing VPN, proxy, shared listener or
  kernel tunnel. If multiple system-wide VPNs conflict, use the
  proxy-only/bridge arrangement rather than starting a second system TUN.
- Source-level regression tests cover occupied default listeners, secret
  backup integrity, invalid/wrong passwords, preserved valid identities,
  Android legacy migration, and native core startup. A real Windows
  Windscribe/ISP and physical Android deployment still require manual
  acceptance measurements.
