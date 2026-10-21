# Android adaptive routing and optional manual diagnostics

**Updated 2026-10-21:** Balanced and Fast do not run a preconnection website sweep, target calibration, cached-profile prerequisite or frozen target selection. Existing website diagnostics never prevent connecting or lock a live route. This does **not** mean every subsystem is calibration-free: on-demand Aether MASQUE exit discovery can run a separate TLS-shape/F&F calibration when its network cache is missing or stale (up to 15 seconds). There is no AI/TikTok-specific route rule; these destinations follow the selected mode like other hosts.

## Connection behavior

Balanced uses the normal preferred-route head start; Fast uses a shorter 125 ms head start. Both learn per destination and can hedge to other eligible methods. Both retain adaptive ByeDPI strategies and the shared Fronter's family hedging. Exact-host fronting consent, CA constraints, native-app certificate trust and foreign-exit restrictions remain in force.

No generic landing-page check or periodic website sweep runs during connection startup or the connected session. Strict foreign modes still verify a neutral exit; that trust check is independent of website diagnostics. A listener or a successful page request does not prove an authenticated feed, profile pagination or playback.

## Optional diagnostics

The disconnected **Test routes** action measures the configured methods and target URLs and stores private observations. Only this explicit action starts calibration traffic. The results panel is historical diagnostic evidence, not a connection prerequisite or a routing pin. A changed target list, old/incompatible profile or failed manual test cannot block ordinary Balanced connection. Method isolation during this manual test uses fixed ByeDPI flags; connected Balanced and Fast retain the original adaptive flags.

The connected **Check HTTPS endpoints** action is also explicit. Its result is per URL and must not be labelled full service access. Protected-exit lease refresh, encrypted DNS, UDP eligibility, exact-host CA rejection and native-helper lifecycle remain separate requirements. Underlying-network changes still require reconnecting to refresh transport and DNS state.

## X and TikTok

The X HTML shell, API calls, images and video are separate paths. ECH now hedges certificate-verified handshakes over known Cloudflare edges before waiting for filtered DNS, so an API route does not lose its entire attempt budget to a poisoned lookup. Tests cover a silent TCP edge losing to a working ECH alternative. Account/API refusals still need to be distinguished from network errors.

TikTok HTTP 451 or a closed connection is not working access. Local fragmentation or ECH does not establish a foreign exit. For a service that requires a foreign IP, choose **Aether to Psiphon** or **Aether to Tor** and verify page, API and media separately; ordinary Aether WARP may geolocate to Iran. There is no AI/TikTok-specific exception in Balanced/Fast.

## Custom targets, CA coverage and evidence

Custom HTTPS targets are exact host/port observations. Normal diagnostics can inspect an unsupported fronting host, but adding a URL cannot make it a supported CDN family. Optional custom-host fronting must already match an existing strategy in `internal/front/rules.go`, remain within the existing local CA's permitted host constraints, and satisfy protected-domain policy. It does not authorize arbitrary hosts/subdomains, modify CA constraints, or regenerate the CA automatically.

The APK signing key and the local MITM CA private key are separate identities. A matching Android user-CA fingerprint proves installation of the public CA certificate, not that another app accepts it. Android app trust settings and certificate pinning can reject that CA. The private CA key remains in app-private storage and is never exported through the document picker. See [preview signing and migration](../android/README.md#stable-preview-signing-and-updates) before updating an older installation.

Assessments describe only what was measured. HTTP refusals such as 403/421 are service responses, not successful content access or evidence of the censorship layer. A provider's successful HTTPS response is not proof that an arbitrary HTTP Host can be fronted through that edge. Opening Telegram's website/Web target or a TikTok page does not demonstrate native-app MTProto, authentication, media delivery, push notifications, or sustained operation. Those need separate application/device measurements.

## CDN scan and CSV export

CDN scanning reuses `internal/edges` and `probe.Run` with six concurrent requests and four-second request timeouts. It is separate from selecting or changing a connected route.

- A finite chosen budget consumes that many unique candidates unless canceled or the real source inventory ends. There is no ten-success stopping rule.
- The slider maximum maps to **budget `0`**: no candidate-count cap and no hidden 90-second session deadline. The scan stops on manual cancellation, actual inventory exhaustion, or a reported storage/discovery failure.
- Cloudflare's known official IPv4 ranges are iterated lazily and uniquely with cancellation. Akamai's attributed seed pool and Fastly/Google DNS answers are finite; they are not expanded into invented prefixes or repeatedly recycled to simulate an infinite inventory.
- Per-IP records preserve TCP, TLS and overall elapsed milliseconds, HTTP status, TLS/HTTP verification flags, an assessment and a fixed error category. Session elapsed time advances during idle periods too. TCP-only reachability, untrusted TLS, HTTP refusals and incomplete responses are not green provider HTTPS results.
- Live status retains the fastest 100 provider-HTTPS verified records plus 20 recent failures. The total verified count is independent of this bounded list. All started attempts stream to an app-private CSV, including in-flight requests drained during cancellation.
- After completion/cancellation, Android's save picker copies the **complete finished CSV snapshot**, rather than exporting only the visible rows. An active/failed snapshot is not exposed as a completed export. CSV fields are `ip,tcp_ms,tls_ms,elapsed_ms,http_status,tls_verified,http_verified,assessment,error`; raw response bodies, credentials and raw diagnostic content are not recorded.

Previously verified provider edges can be loaded as source-backed preconnection candidates. They still require validation against the actual target before any fronting claim or use. Saving or exporting a CDN scan does not alter the active route.

## Candidate acceptance remains open

The final phone check must verify immediate adaptive Balanced/Fast startup without a website-target sweep; separately measure first-use Aether TLS-shape calibration; optional manual tests and cancellation; target edits without a mandatory test; fallback after helper failure; same-exit verification refresh and fail-closed failures; exact-host CA rejection; continuous-scan cancellation and full picker export; and a same-signer in-place update retaining the local CA. Also check real profiles, pagination, new posts, native-app media, helper lifecycle, reconnect, DNS/IPv6/UDP leaks and battery behavior on the intended phone/network. Source tests and builds do not establish those device results.
