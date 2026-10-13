# Evidence and design notes (reviewed 2026-10-13)

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
