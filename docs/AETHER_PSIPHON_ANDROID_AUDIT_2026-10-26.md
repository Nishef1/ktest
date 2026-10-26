# Aether / Psiphon Android mode audit — 2026-10-26

Compared KTest Go/Android mode handling against patterniha/PattNG at commit 3b657ff and patterniha/PattN 7.25.6-P37. PattNG keeps key renewal independent of a server profile and handles an isolated key-selection/registration UI; KTest keeps a separate app-private identity folder and shared policy.

## Confirmed integration defects repaired

1. Psiphon Auto UI claimed "WARP first, then standalone" but its implemented sequential ladder was never called from the Android session launcher. The default launcher selected one representative profile. The launcher now calls the bounded, exit-verified Psiphon ladder.
2. The WARP-first flag was difficult to interpret; it now controls **Psiphon Auto** only. New installs begin with independent Psiphon CDN; users can explicitly choose WARP-first, using saved valid WARP keys only. No keys means no pointless WARP chain before CDN. Explicit Psiphon-through-WARP remains intentionally strict.
3. An optional Fast carrier failing to start used to abort every native exit before independent connection attempts. Fast failure now falls back to direct native routes. An H2 carrier option no longer removes direct H3/WireGuard from explicitly selected transports. Standalone Psiphon additionally retries without Fast if a running local carrier fails upstream.
4. The prior static Aether v2.3.5 notice in Settings was stale after v2.4.0 rollout.
5. Manual "Get WARP key" attempted both protocols, hiding a working MASQUE key behind failed WireGuard registration, and offered fewer fallback routes than Android auto-enrollment. MASQUE and WireGuard registration/status are now independent; direct API, fragmented TLS, conditional ECH and conditional Psiphon CDN routes are attempted sequentially as available.

## Connection precedence visible in Android

- **Aether (WARP):** WARP MASQUE H2/H3 and WireGuard only; keys required. Optional Fast is an additional TCP/H2 first hop, never an H3 or WG carrier.
- **Psiphon, Auto, CDN first (default):** independent CDN Psiphon routes; no WARP key. Optional Fast first hop and direct fallback are separate from WARP.
- **Psiphon, Auto, WARP first:** only when a valid identity exists, try Psiphon through WARP, then independent CDN. If WARP keys are missing, CDN is tried without auto-registering WARP merely to run Psiphon.
- **Explicit Psiphon-through-WARP:** requires WARP credentials. No silent method switching.
- **Tor:** Tor-only; local Fast optional, no WARP dependency.
- **Settings → WARP keys:** provision individual MASQUE/WireGuard keys, separate from tunnel and egress verification.

## Release gates

- Go unit, race, formatter, Windows, Android source and actual Android JNI/APK CI must pass at the merged commit.
- Live physical Android 10 (API 29) testing remains necessary: registration and saved-key permissions, independent CDN Psiphon, WARP-first with and without saved keys, H2/H3/WireGuard, Wi-Fi/cellular, cancellation, cross-screen status, full-VPN vs proxy-only, foreign-egress verification, and encrypted backup roundtrip.
- A new preview gets versionCode 23, versionName 0.5.3-preview, and uses the same private preview signing identity as the previous APK. Do not uninstall, clear app data, or claim universal ISP bypass.
