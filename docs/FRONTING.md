# Fronting engineering decisions — 2026-10-15

Status: architecture confirmed against upstream docs; limited IP candidate selection implemented; four transports are NOT yet merged or field-verified on Iranian ISPs.

## Mechanisms: do not confuse layers

- **CDN domain fronting:** TLS SNI names one virtual site, HTTP Host/:authority identifies a different origin on a shared edge. It works only where provider routing and anti-abuse restrictions allow the mapping. CloudFront explicitly rejects some mismatches as HTTP 421: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html
- **Local MITM:** local Xray terminates the application's HTTPS and opens a new outbound TLS channel. It requires a private, locally generated CA and explicit user trust. Upstream Xray MITM profile: https://github.com/patterniha/MITM-DomainFronting/blob/main/Xray-config/MITM-DomainFronting.json
- **TLS record slicing vs TCP slicing:** these are different implementation layers; preserve valid TLS framing and certificate verification. Compare Xray's existing fragmentation features before modifying record serialization. 2025 paper: https://ris.uni-paderborn.de/record/59824 ; reproducible tooling: https://github.com/tls-attacker/Censor-Scanner
- **Domain shadowing** (sometimes loosely described as shadow fronting): configure an owned front domain/CDN route to an origin target. It can coexist with domain fronting but it is not a no-account arbitrary-site SNI trick. USENIX 2021: https://www.usenix.org/conference/usenixsecurity21/presentation/wei
- **IP allowlisting:** no above change restores IP paths that the ISP outright blocks. RANDLab Iran 2026: https://randlab.engineering.ucsc.edu/blogs/iran-allowlist/

## IP health: implementation and interpretation

Source candidates from known DNS answers or **official** published CDN ranges (e.g. https://developers.cloudflare.com/api/resources/ips/). Never assume that membership in a provider's prefix proves the edge can serve a specific origin. Keep sampling small and permitted; some CDNs route differently by region and IPv4/IPv6.

```sh
ktest edges -authorized -url https://your-controlled-domain.example/__ktest/proof \
  -ips 192.0.2.1,2001:db8::1 -rounds 2 -proof
```

Addresses above are documentation-only (RFC 5737 and RFC 3849); replace them with authorized, confirmed endpoint candidates. To compare a *known* front domain and an owned target, explicitly pass `-sni front.example` and `-host target.example`. The client validates TLS against **the chosen SNI**, not automatically against the Host; use `-proof` and a controlled server to establish that the intended origin answered. A matching 2xx alone is never proof of correct CDN routing.

The output orders candidates by `origin_verified`, `http_2xx_unverified`, `tls_only`, `tcp_only`, `unreachable`. This is a bounded convenience selector, NOT an active DPI fingerprinting engine or broad network scanner. Compare each selected edge again through the intended Xray profile before calling it operational. TCP measurements are embedded in each HTTPS attempt; no redundant ICMP ping.

## Certificate handling: not software licensing

**MITM local CA**: generate on-device, never use an online certificate-generation website or import an unknown CA:

```sh
xray tls cert -ca -file=mycert
```

This creates a local certificate and private key; use the actual filename conventions of the installed Xray release. Never commit `*.key` or `mycert.crt` to GitHub. Keep permissions restrictive. User explicitly opts into trust within their chosen browser/OS. Prefer a separate browser profile where feasible; remove the local CA when not using MITM. Some apps refuse user CAs due to pinning; do not attempt to silently disable pinning. If the remote origin certificate is not verified, fail closed. The initial MMDF README admitted missing upstream certificate validation and is **not** a safe implementation to ship unchanged: https://github.com/patterniha/MMDF

**Owned shadow/CDN domain**: obtain a public, origin-valid TLS certificate via a provider or ACME/Let's Encrypt, with domain control verified through DNS-01/HTTP-01 as applicable. A public certificate is different from a local MITM CA. This may require registration fees, CDN accounts or bandwidth charges; generating a local CA does not authorize domain ownership.

**Software licenses**: a repository's `LICENSE` is separate from cryptographic certificates. Xray uses MPL-2.0, Lantern domainfront Apache-2.0, and some upstream components GPL-3.0; review compliance before copying code.

## Proxy or tunnel?

- **Default: loopback-only HTTP CONNECT/SOCKS5 proxy** (Xray's existing mixed inbound); works for apps configured to use it, preserves per-service routing, needs no TUN drivers.
- **Shadowing / CDN relay:** requires a CDN service under our control and can forward HTTP(S) or a purpose-built stream. It is a separate operating mode, not always serverless.
- **Full-system TUN/transparent routing:** not necessary to unlock individual sites; OS adapters are inherently different across Windows/Linux/macOS. A local HTTP proxy alone does not automatically carry WireGuard UDP or make Windscribe connect.
- Design must be fail-closed: failed fronting never means silently falling back to direct for a domain that users explicitly routed through fronting.

## Remaining, evidence-based gates

1. Confirm Xray MITM v23 profile's current syntax and outbound certificate validation before integrating any CA workflow.
2. Use explicit, controlled provider-to-origin mappings; differentiate 421/403 from successful CDN routing.
3. Only then add optional TLS slicing for the affected TLS handshake paths, not globally.
4. Integrate domain shadowing **only** when a front domain, CDN account and permitted origin are available; do not market it as free arbitrary-origin access.
5. Real 2026 Iran ISP outcomes must be labeled unverified until observed on the user's network.

## Operator-visible claims

- A successful ECH/API enrollment proves credential preparation, not reachability of WARP data-plane gateways.
- A CDN/front probe returning a plausible response is a candidate, not independent proof that an arbitrary requested origin was reached.
- Local root-CA installation grants interception capability to its private-key holder. Offer it only for explicit website-fronting workflows and never as an Aether/WARP tunnel repair step.
- If the system DNS returns a private block-page address, mark the DNS path suspicious and separately verify any replacement encrypted resolver. Do not claim it works before a live check.

## Name constraints are not a universal root-CA security boundary

The locally generated certificate requests X.509 permitted-domain name constraints. Browsers, OS trust stores and TLS implementations may treat explicitly trusted root anchors differently. It is **not** safe to claim that an installed root key can never issue a certificate accepted for other domains merely because the root certificate embeds these constraints. Protect the local CA private key, use only the explicit optional fronting workflow, and uninstall the root when it is no longer needed. A genuine external WARP tunnel does not require this root.
