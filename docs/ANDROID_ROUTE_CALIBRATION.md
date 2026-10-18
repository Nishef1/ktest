# Android Balanced/Fast route calibration

This describes the Android Balanced and Fast contract in the Go route planner, bridge and proxy. It does not change the other native modes or establish physical-phone acceptance. Source tests, an APK build, or an emulator observation cannot establish native-app access, whole-device leak protection, or production readiness. The main integration report must record final verification for the actual signed candidate.

## Before connecting

1. Load the saved target list and the currently available methods. A new or expired profile can be calibrated during connection preparation; a compatible fresh profile is reused without probe traffic.
2. Test **every eligible method/target pair once** before selecting a winner. A method must match the target and satisfy existing policy; protected services require an eligible verified foreign exit. Ineligible pairs are recorded as not applicable, rather than reported as failed network paths.
3. Select up to three responsive finalists per target and give each two more independent trials: **three trials total per finalist**, including the first pass. Rank the observed reliability, HTTP outcome, latency and jitter. TCP acceptance or a TLS handshake alone is not successful content access.
4. Save one private profile with per-target selections and an observed generic route for unknown destinations. The cache lasts **24 hours** and is shared by Balanced and Fast, subject to matching target/method configuration and available methods. Switching between those modes does not by itself request another test.

The manual **Test** action is an override of cache reuse and works only while disconnected, including when the profile is still fresh. It prepares the existing cores for measurement, saves the observations and tears down the test resources; it does not establish a connected VPN session. Status polling is a read operation and does not send new probe traffic. Changes to the target/method set while a cached profile is fresh require an explicit manual test before connecting. An unreadable/incompatible cache or a clock earlier than its recorded test likewise requires explicit action.

## During a connected session

Balanced/Fast keep the selected method for each target fixed. They do not launch automatic route tests, discovery races, method hedges, retries through other methods, or background cache refreshes. Manual tests and target edits require disconnection. A selected native helper failing does not silently select a different method; disconnect, inspect the failure and explicitly retest before reconnecting.

Fixed Android ByeDPI entries strip adaptive `--auto`/`--auto-mode` flags before launching and label the effective fixed flags, so a selected child cannot internally relearn or reset its strategy while connected. Plain transport is a separate tested method. This constraint applies to Android's frozen Balanced/Fast route plan; Windows and other non-frozen legacy paths retain their existing behavior.

The route-profile lifetime is separate from the verified foreign-exit lease. Protected traffic still requires valid exit evidence. When that lease expires, the fixed session fails closed for traffic that needs it: it does not verify the exit live, switch routes, or fall back to a direct/local path. Disconnect and run an explicit test before reusing the exit. A fresh 24-hour route profile does not extend an exit lease or prove the current location of an exit.

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

The final phone check must distinguish observed source/test results from actual behavior: complete preconnection coverage and repeated trials; reuse across Balanced/Fast within 24 hours; disconnected manual override and target edits; absence of connected-session tests/switches; fail-closed exit expiry; exact-host/CA rejection; continuous-scan cancellation and full picker export; and same-signer in-place update retaining the local CA. Also check the real native apps, native helper lifecycle, reconnect, DNS/IPv6/UDP leaks and battery behavior on the intended phone/network. This document records the contract and verification boundary, not completion of those checks.
