# Android WARP identity publication fix — 2026-10-26

## Observed failure

On a real Android app install, Aether completed a staged WireGuard identity registration but publication failed on `os.Link`: `permission denied` from `files/aether/.enroll-*/wg.toml` to `files/aether/wg.toml`. It was incorrectly surfaced as an inability to get a key over any WARP API/anti-DPI route. No evidence from this log proves the selected ISP blocked registration; the hardlink failure is local.

## Fix and failure boundaries

- Registration and encrypted backup restore/migration use one shared credential-publishing routine. It checks the staged key, attempts atomic hardlink on permitted filesystems, then falls back to private O_EXCL creation if links are blocked.
- The fallback checks each byte written, fsyncs, closes, validates the final identity and cleans up newly created files after ordinary failures. Existing valid or invalid identity filenames are never overwritten. Abrupt process/power failure during exclusive copy could leave an incomplete file that deliberately requires explicit repair; never auto-delete a saved identity.
- Regression tests simulate `os.Link` returning EPERM, repeated registration, invalid existing files, and invalid staged keys. Tests are portable but do **not** simulate the actual device's SELinux/filesystem.
- Android preview versionCode advances to 22 (0.5.2-preview), preserving upgrade eligibility from signed versionCode 21 when signing keys match.

## Live acceptance

1. Install the newly signed 0.5.2-preview APK over 0.5.1-preview without uninstalling or clearing app data.
2. Disconnect, use Settings → WARP identity recovery → Get WARP key with blank proxy. Ensure MASQUE and WG keys report valid without `cannot publish identity`.
3. In Aether, choose Auto first (not WireGuard-only); compare H2 and WireGuard afterward. Verify real HTTPS egress separately from the local SOCKS listener. No universal connection guarantee.
4. Run independent Psiphon CDN/standalone and chained profiles, record redacted error categories; a WARP identity fix does not prove Psiphon/CDN traverses the ISP. Explicitly check foreign exit where required.
5. Repeat on Wi-Fi and cellular, screen off/on, cancel, disconnect, handover and network loss; inspect app startup lifecycle and preserved identities.

## Status

Code-level fix, not real-device validation. App cannot bypass every ISP by virtue of a WARP API edge. Do not infer carrier accessibility from successful enrollment.
