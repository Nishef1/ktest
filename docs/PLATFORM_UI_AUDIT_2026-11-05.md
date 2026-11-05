# Platform UI audit — 2026-11-05

Scope: KTest Android Jetpack Compose screens, Windows portable terminal UI,
and their user-facing connection/coverage wording. Audited current main after
the PattNG core alignment. This document is a source-level review: build CI is
required for validation, and no emulator screenshots or physical-network
success are inferred from source compilation.

## Android corrections

- **Primary-action hierarchy:** the large Connect/Disconnect control now
  precedes the public-IP diagnostic panel, avoiding a forced scroll before
  the primary action on short displays. The orb adapts to compact height.
- **Touch areas:** the shared segmented control, secondary button, alert
  dismissal, IP refresh, method selection and advanced selectors have at
  least 48 dp interactive dimensions. A proxy address is now one large
  clickable row rather than nested row-plus-icon buttons.
- **Legibility:** the secondary "faint" text token moved from #5A6A78
  (approximately 3.3:1 on #0D151D) to #748694 (approximately 4.9:1).
  The rest of the dark palette and the connection-state colors are retained.
- **System insets and keyboard:** the bottom navigation overlay is hidden
  while the software keyboard is open; the content maintains IME padding.
- **Accessibility:** selected tab and segment semantics are exposed,
  and the copyable proxy row has a single announced action.
- **Truthful scope labels:** the UI no longer says that VPN routing includes
  KTest's own excluded UID. Non-DNS UDP is described as gated by approved
  relay or tunnel availability; unsupported traffic is blocked, not
  guaranteed to fall back to TCP.

## Windows portable console corrections

Windows is a terminal-first executable, not a native graphical desktop app.
It does not have pixel layouts to redesign. The menu now states the
selected coverage beside the saved policy, reports Whole PC as a beta
Admin-required mode, and stops implying that Aether/WARP is automatically
Psiphon. Long summaries are included in the alternate-screen height budget
to avoid clipping on short terminals. Regression tests cover coverage and
Aether wording.

## References and acceptance gates

- Android Compose touch targets: https://developer.android.com/develop/ui/compose/accessibility/api-defaults
- Android edge-to-edge/IME: https://developer.android.com/develop/ui/compose/system/setup-e2e
- WCAG 2.2 text contrast minimum: https://www.w3.org/TR/WCAG22/#contrast-minimum

Source/build gates: Go tests, race, vet, Android source/manifest compilation,
signed APK and checksum verification, Windows ZIP packaging and CLI menu tests.

Still required on hardware: Android small/large screens, landscape and split
screen, 1.5x–2x font scale, TalkBack, keyboard focus in Settings/Tools, USB
keyboard/D-pad, system gesture and 3-button navigation, VPN permission revoke,
reconnect and Wi-Fi↔cellular handover, packet DNS/UDP/IPv6 and leak tests.
For Windows: 80x24 and narrow console sizes, high contrast, disabled VT/NO_COLOR,
screen-reader speech order, UAC/TUN permission and cleanup after interruption.
Network success must be measured on the actual ISP using comparable profiles;
CI never proves censorship bypass.

## Settings and Tools follow-up

- Corrected stale native-core attribution: Xray is the PattNG v26.11.1
  fork and HEV is 2.19.3.
- The "Verify Aether bundle" action accurately describes its scope:
  Aether, Psiphon and Lyrebird. It does not claim to validate every
  library in the APK; Xray/ByeDPI are runtime-validated independently.
- Removed a duplicated "preview" version suffix, enlarged settings rows,
  used a numeric keyboard for port fields and made linked source notices
  single accessible tap targets.
- Replaced seven cramped CDN provider segmented options across two rows
  with one accessible dropdown, and made copyable edge addresses one
  minimum-48dp tap target.
