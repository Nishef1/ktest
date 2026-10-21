# Evidence and design notes (reviewed 2026-10-13)

> **Current implementation note (2026-10-21):** this document records research and hypotheses, not proof of a working bypass. The current code has no AI/TikTok-specific routing rule; use [connection-mode contracts](CONNECTION_MODES.md) for actual behavior and [CURRENT_AUDIT_2026-10-21.md](CURRENT_AUDIT_2026-10-21.md) for CI status, known implementation issues and unmeasured performance. Historical research results must not be promoted to current ISP guarantees.

All external claims below are from linked public sources. **No field success has been demonstrated by this repository.** Issue reports are anecdotal, and tool availability is not proof of effectiveness on a given ISP.

| Technique / source | What is supported | Limit for our use | Evidence |
| --- | --- | --- | --- |
| SNI-Spoofing-Go | A Go local TCP forwarder using injected decoy ClientHello / SNI and optional uTLS profiles | Different mechanism than a conventional HTTP client; administrative/raw packet access; results dependent on path and ISP | https://github.com/aleskxyz/SNI-Spoofing-Go |
| patterniha MITM-DomainFronting | Access to selected HTTPS services by local TLS interception and separate upstream handling; author-provided config | Requires trust-root installation; not a universal tunnel; users reported failures in Aug 2026 | https://github.com/patterniha/MITM-DomainFronting ; https://github.com/patterniha/MITM-DomainFronting/issues/191 |
| Zapret2 | Packet manipulation/desynchronization with nfqws2 and Lua strategies | Platform-specific packet privileges, edge cases, false positives; cannot invent blocked IP routes | https://github.com/bol-van/zapret2/blob/master/docs/readme.md |
| Transport Layer Obscurity (IEEE S&P 2025) | 38 partially standard-compliant circumvention techniques grouped into 11 categories; tests in China and Iran | Past experimental results, not blanket support under 2026 allowlists | https://ris.uni-paderborn.de/record/59824 ; https://ieeexplore.ieee.org/document/11023326 |
| RANDLab Iran allowlist study (June 18, 2026) | Evidence of restrictive routing/allowlisting and layered SNI interference from studied vantage points | Cannot generalize all networks/dates, not a client-side bypass recipe | https://randlab.engineering.ucsc.edu/blogs/iran-allowlist/ |
| CloudFront fronting controls | The provider performs SNI/Host/certificate/account checks and can issue HTTP 421 on rejected fronting requests | CDN behavior belongs to provider and may change; normal fronting cannot be assumed | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html |
| ECH | ECH hides the inner ClientHello when supported by an actual ECH server; configuration can be provisioned | Cannot forge authorization, choose arbitrary foreign exit, or bypass upstream IP policy | https://www.rfc-editor.org/rfc/rfc9849.html |

## What is NOT established

- That a specific 2026 Iranian ISP currently allows domain fronting or will remain reachable.
- That exchanging HTTP Host and TLS SNI with a selected CDN always routes to a different origin.
- That a Go standard-library HTTP request is DPI desynchronization (it is not).
- That partial access to Google Drive, Apps Script or a website equals system-wide foreign egress.
- That third-party root CA or `InsecureSkipVerify` is acceptable in a production client.

## Controlled experiment types

A. Baseline HTTPS request using normal DNS and TLS identity.

B. Identical HTTPS request with pinned TCP destination IP (for controlled infrastructure); TLS name and Host unchanged. Distinguishes name resolution/routing but does not constitute an exploit.

C. Identical TCP destination with a deliberate TLS name and/or HTTP Host variation, only for targets that we operate or are authorized to test. Record certificate validation, status and protocol. This tests *server/CDN routing behavior*, not the packet-level SNI injection of SNI-Spoofing-Go.

D. Later, compare a third-party packet-desync tool to the baseline under exactly the same path, with reversible opt-in setup. No bundled third-party binaries until provenance/security review.

## Security constraints

- We must not upload packet captures containing credentials, per-user network addresses, private bridge details, or tokens to this public repo.
- Do not weaken TLS verification just to make a routing test appear to work.
- Tests should have strict timeouts, response limits, and low request counts.

## Research update: QUICstep and nuanced failure classification (2026-10-13)

- **QUICstep (PETS 2026; July 20, updated September 12):** a real proof-of-concept that uses a temporary censorship-resilient path for the QUIC handshake, then migrates a validated connection to another network path. Only feasible when the final direct UDP path works, the server supports QUIC connection migration, and a bootstrap path exists. The paper reports performance benefits under its specific experimental conditions; there is **no demonstration** that this grants access under Iran's 2026 source-IP allowlist. References: https://gfw.report/publications/pets26a/en/ and https://github.com/inspire-group/QUICstep
- **Insights into an Iranian Internet Shutdown (FOCI 2026):** DNS, HTTP, TLS and QUIC policies varied across the June 2025 disruption; measuring the protocol failure phase is more valuable than assuming one DPI rule for all traffic. https://www.petsymposium.org/foci/2026/foci-2026-0016.php
- **Iran allowlist early findings (RANDLab, June 18 2026):** important source-vantage limitations. Even a fully valid TLS variation does not cross an IP layer that drops packets. https://randlab.engineering.ucsc.edu/blogs/iran-allowlist/
- **Zapret2 latest checked 2026-10-13:** stable GitHub release v1.0.5.2, not necessarily latest commit in its development branch. **SNI-Spoofing-Go:** latest tagged v0.7.2. No third-party binaries copied into this repository. https://github.com/bol-van/zapret2/releases and https://github.com/aleskxyz/SNI-Spoofing-Go/releases

### Novel synthesis (hypotheses, **not** observed bypasses)

1. **Verified-origin differential:** instrument paired route/SNI/Host tests with fresh nonces so that ISP block pages, captive portals, CDN misrouting and ordinary HTTP redirects do not appear as wins. Implemented in this repository.
2. **Failure-aware exploration:** stop experimenting with TLS when no TCP route exists. Use structured failure signals to determine the next *controlled* experiment instead of selecting tricks at random. Implemented as a conservative summary, with no automatic traffic manipulation.
3. **Partial-channel handshake bootstrap:** if an independently working VPN/mobile link can carry a QUIC handshake, research whether QUICstep can migrate data to a direct path. Requires compatible origin and usable post-migration path; research only, no code implemented.


## Additional research cross-check — 2026-10-13

- **IRBlock** documents independent DNS injection, HTTP block-page injection, HTTPS TCP reset injection and QUIC/UDP-drop observations. It measures by provoking bidirectional filtering from outside Iran; the maintainers explicitly warn that the results are a *lower bound* on restrictions users inside Iran may face. https://irblock.org/
- **Insights into an Iranian Internet Shutdown** (Paderborn University; FOCI 2026) reports nonidentical timing for DNS-over-TCP, TLS, QUIC and UDP interference around the June 2025 Iran shutdown, supporting phase-separated experiments. It is historical data, not proof of network conditions today. https://www.petsymposium.org/foci/2026/foci-2026-0016.php
- **QUICstep** (PoPETs 2026) publishes a functional, reproducible QUIC connection-migration prototype that hides its handshake through a secure channel before migrating to a separate path. Limitations: secure bootstrap path, compatible QUIC peer and working direct data path. The paper is not evidence that IP allowlisting is bypassable. https://www.petsymposium.org/popets/2026/popets-2026-0014.php and https://github.com/inspire-group/QUICstep-PETS
- **Zapret2 v1.0.5.2** remains the latest tagged release confirmed on 2026-10-13; check newest commits separately when integrating. https://github.com/bol-van/zapret2/releases

### Rejected shortcuts

- HTTP `200` cannot validate the origin by itself; a captive portal or block page could be returned. Use the controlled nonce challenge for application-layer origin evidence.
- A TCP SYN/SYN-ACK exchange does not validate TLS or HTTP. Conversely, TLS failure may be certificate rejection or server misconfiguration, not necessarily a DPI action.
- Silent UDP does not by itself demonstrate UDP blocking; UDP has no mandatory delivery acknowledgement. We did not add a misleading generic `UDP works` button.
