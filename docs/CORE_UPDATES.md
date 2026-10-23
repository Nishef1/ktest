# Updating native cores safely

**Current acceptance boundary (2026-10-21):** Aether v2.3.2 and Xray-core v26.10.21 are separately pinned; updating Aether does not update Xray, HEV or ByeDPI. Current CI passed on commit `978e0ab`, but this does not establish live foreign egress, Android physical-device stability, or performance. See [the current audit](CURRENT_AUDIT_2026-10-21.md).

KTest does not update a live tunnel in-place. Release pins are explicit in
source control, and the Windows portable and Android builds independently
verify the artifacts they distribute. KTest never fetches an unsigned
"latest" Aether binary at connection time.

## Aether v2.3.5 (2026-10-23)

v2.3.3 adds licence files; v2.3.4 holds all listening ports from start (Psiphon/Tor now sit behind a port Aether holds) and ends Aether when an in-tunnel Tor/Psiphon stops; v2.3.5 fixes port-0 binds and wildcard listeners. CLI options are unchanged, so profiles are unchanged. Both locks were regenerated with `update-aether-release.py --write`.

## Aether v2.3.2 (2026-10-21)

Release source: https://github.com/patterniha/Aether/releases/tag/v2.3.2

This release changes Windows runtime linking; its documented CLI and
tunnel protocols match v2.3.1. The working v2.3.1 core remains supported as a
**legacy fallback** on desktops until the new generation is available.

- Desktop lock: `internal/aether/desktop-cores.json`, consumed by Go and
  the Windows portable build. Every platform archive is SHA-256 pinned.
- Android lock: `internal/aether/android-cores.json`, checked by the native
  packager and the Go runtime. Every archive **and every extracted executable**
  is SHA-256 pinned, with architecture and load alignment checked too.
- Windows first-use/upgrade writes the complete Aether + Psiphon + Lyrebird
  generation under `cores/aether-versions/v2.3.2/`, beside any
  `cores/aether.exe` legacy fallback, rather than overwriting an executable
  that might be running. It creates `aether-release.sha256` only after all
  three binaries have staged and publishes the whole directory in one rename.
  Failed downloads and partial packages preserve the previous files.
- The portable Windows CI uses the same versioned layout. Every new
  connection selects the complete pinned generation, while an existing
  connection holds the executable it already launched.
- Android executables stay inside the signed APK's `nativeLibraryDir`.
  Updating an Aether executable on Android requires a new signed app build,
  **not** downloading a new native executable to writable files or changing
  the running VPN process.
- Private WARP identities, including nested identities, remain under the
  per-user configuration directory on desktop, and Android app-private
  storage on phones. Neither installer touches them.

### User commands

`ktest warp` displays the current identity status and the installed
generation. `ktest warp -upgrade` stages the newer *pinned* generation
without registering or deleting any WARP identity. `ktest warp -enable`
may also install the pinned generation when running Setup. Close and restart
the connection to begin using newly installed files. The Setup menu accepts
`u` to perform the same update.

For an immediate rollback on Windows, start a fresh PowerShell with
`$env:KTEST_AETHER_USE_LEGACY = "1"` and launch KTest again. This selects
`cores/aether.exe` and its matching `cores/pt/` helpers when they exist.
Clear the variable with `Remove-Item Env:KTEST_AETHER_USE_LEGACY` to
select the new pinned generation again. **The override changes only
which files new connections launch; it never deletes the newer version or
a saved WARP identity.** For releases without a legacy core, it is a no-op.

An in-progress core continues to use its existing executable. Never remove
an older directory while its process may be running. Keep old versions for
manual rollback; do not clean old directories automatically after an update.

### Developer upgrade procedure

1. Create a feature branch from `main`. Choose a stable published Aether
   release and review its changelog, changed options, dependencies,
   permissions, platform architectures and licenses.
2. On a trusted build machine, run
   `python3 android/scripts/update-aether-release.py --version vX.Y.Z`.
   It is a **dry run** unless `--write` is passed. It checks GitHub release
   asset SHA-256 digests, downloads all three Android archives, verifies each
   ELF and calculates hashes of Aether, Psiphon and Lyrebird. It also pins
   the published desktop assets.
3. Review, then run with `--write`, or use the manually triggered
   **Update Aether Android lock** GitHub Action on the feature branch.
   The Action refuses to write directly to `main`.
4. Update release notes and version references if needed. Raise Android
   versionCode/versionName and align the preview APK assertions only when
   shipping a new APK.
5. Run Go tests, Windows portable smoke, Android JNI/Kotlin build, and
   verify-apk hash checks in CI. On devices, verify WARP enrollment,
   H2/H3/WG, reconnect, mobile network switching, packet DNS and Windscribe
   carrier behavior. Working on one filtered ISP is not proof of universal
   availability.
6. Merge only when branch checks pass. A future binary update that changes
   CLI flags requires adapting profiles and adding tests before upgrading.

**Do not** point production to a floating `latest` URL, trust a new archive
just because its filename resembles the last one, or delete user identities
during an executable update.

## Other native cores

Xray, ByeDPI, sing-box, Wintun and Zapret2 still have their own **separately
pinned** releases and package checks. The Aether update process does not
silently update, remove or replace those components. Generalizing the
manifest updater to their upstream formats should be a reviewed change per
component, not a bulk replacement that endangers the working Aether paths.

## Dead-artifact cleanup

The generated `cmd/ktest/ktest.exe` is no longer committed to source
control. CI produces Windows executables and downloadable ZIP artifacts.
The disabled `binaries` job in the verification workflow was removed;
production Windows and Android build workflows are unaffected. No currently
used profile, helper or backward-compatible API was deleted merely because
it looked old.
