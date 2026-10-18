# Android Fast adaptive routing and Balanced route calibration

This describes the intentionally distinct Android Fast (live adaptive) and Balanced (preconnection calibrated) contracts in the Go route planner, bridge and proxy. It does not change the other native modes or establish physical-phone acceptance. Source tests, an APK build, or an emulator observation cannot establish native-app access, whole-device leak protection, or production readiness. The main integration report must record final verification for the actual signed candidate.

## Fast: immediate adaptive connection

Fast retains the pre-calibration Go SmartProxy strategy race, learned per-destination routing, original adaptive ByeDPI strategies, optional local Xray fragmentation and front-family hedging. Fast does **not** perform Frozen Route calibration, read its cached profile during startup, or pin a single method merely because an earlier Balanced profile exists. It still respects protected-domain verified-foreign-exit requirements, DNS rules, fail-closed non-DNS UDP and exact-host opt-in rules for MITM fronting. Fast is not permission to leak traffic outside those policies.

## Balanced: before connecting

1. Load the saved target list and available methods. New or expired profiles can be calibrated during connection preparation; a compatible fresh profile is reused without probe traffic. Initial calibration uses at most four concurrent independent tasks and a three-minute overall startup budget; an incomplete timed-out calibration is never saved.
2. Test **every eligible method/target pair once** before selecting a winner. A method must match the target and satisfy existing policy; protected services require an eligible verified foreign exit. Ineligible pairs are recorded as not applicable, rather than reported as failed network paths.
3. Select up to three **HTTP-successful** finalists per target and give each two further trials: **three trials total per finalist**. Only a method with three successful HTTPS checks is frozen for that exact target. HTTP 403/421, TCP-only, TLS-only and intermittent responses are not selected as stable winners.
4. Save one private Balanced profile with per-target selections and, when verified, a generic route for unknown destinations. The cache lasts **24 hours** and includes the underlying Android network handle/transport in its hashed identity, not an SSID or carrier identifier. Fast never consumes it. A change of network or native method availability causes a new bounded calibration when the user targets remain unchanged.

The manual **Test** action is an override of cache reuse and works only while disconnected, including when the profile is still fresh. It prepares the existing cores for measurement, saves the observations and tears down the test resources; it does not establish a connected VPN session. Status polling is a read operation and does not send new probe traffic. User edits to the target list while a cached profile is fresh require an explicit manual test before connecting. Unchanged targets with a missing or restored native method can be recalibrated automatically within the startup budget. An unreadable/incompatible cache or a clock earlier than its recorded test likewise requires explicit action.

## During a connected Balanced session

Balanced keeps the selected method for each target fixed. It does not launch automatic route tests, discovery races, method hedges, retries through other methods, or background cache refreshes. Manual tests and target edits require disconnection. A selected native helper failing does not silently select a different method; disconnect, inspect the failure and explicitly retest before reconnecting.

Balanced-only fixed Android ByeDPI entries strip adaptive `--auto`/`--auto-mode` flags before launching and label the effective fixed flags, so a selected child cannot internally relearn or reset its strategy while connected. Plain transport is a separate tested method. This constraint applies only to Android Balanced; Fast and Windows legacy routes retain their existing adaptive behavior.

The route-profile lifetime is separate from the verified foreign-exit lease. Protected traffic still requires valid exit evidence. When the lease expires, the fixed session revalidates **the same already-selected foreign exit** under the existing bounded exit-verification policy. It never switches methods or falls back to a direct/local path. A failed verification blocks protected traffic until the same exit verifies successfully or the user reconnects. A fresh 24-hour route profile does not extend an exit lease or prove the current location of an exit.

## Route recovery, UDP and diagnostic limits

- A completely unusable calibration result is not saved as a fresh profile. A verified target-only profile is allowed even without a verified generic route; unmeasured or unknown hosts then fail closed. An exact target with only HTTP refusals does **not** pin the whole hostname to an empty route: the generic route is used if independently verified. Root-page success on X media/API hosts does not prove that authenticated APIs or videos play.
- Balanced's selected TCP route and non-DNS UDP relay have separate eligibility. An available foreign SOCKS5 exit with verified UDP ASSOCIATE may carry UDP/443; a plain local ByeDPI/Xray TCP route may not. No direct ISP UDP fallback was added. A failure to obtain a verified UDP exit may cause the native app to wait before using TCP, but this must be checked on a phone.
- After an underlying network handover, Android stops the Balanced session with a reconnect/recalibration message rather than silently persisting a stale frozen selection. Android's default-network callback is registered only for the session and unregistered during stop/destroy. Physical-device checks must verify it does not misinterpret the app's own VPN activation as a handover.
- Go exposes bounded aggregate counters for TCP events, TLS replies, UDP associations, UDP/443 errors and the last selected method/latency. It does not retain user destination names, credentials or payloads. These counters are evidence of transport events, **not** proof that X used QUIC or that HEV, Xray or the CDN caused a particular delay.
- Fast now learns a positive HTTP/1.x Fronting score only after a response was actually delivered; a 403/421 response is negative. HTTP/2 replies are not interpreted as application-success evidence by this coarse status observer. ECH allows only one retry_config-driven connection, matching RFC 9849's retry guidance. Neither mechanism asserts arbitrary-origin delivery on all CDN edges.

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

The final phone check must distinguish observed source/test results from actual behavior: Fast immediate connection and adaptive selection; Balanced bounded preconnection coverage and repeated trials; Balanced reuse within 24 hours only on an unchanged underlying network; disconnected manual override and target edits; absence of connected-session tests/switches; same-exit verification refresh and fail-closed failures; exact-host/CA rejection; continuous-scan cancellation and full picker export; and same-signer in-place update retaining the local CA. Also check the real native apps, native helper lifecycle, reconnect, DNS/IPv6/UDP leaks and battery behavior on the intended phone/network. This document records the contract and verification boundary, not completion of those checks.
