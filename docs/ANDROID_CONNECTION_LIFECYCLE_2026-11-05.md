# Android lifecycle, notification, and route readiness — 2026-11-05

## Source-level defects addressed

The old ProxyService and KTestVpnService were foreground services with
different notification IDs (42 and 43) and channels. They now use the
same package notification ID (42) and channel. Both remain foreground
services and each still promotes itself promptly. This is intended to
present one active status-bar notification rather than two.

Go proxy listener readiness is not equivalent to public Internet access.
The ProxyService now makes a bounded real HTTPS trace over the SOCKS
policy BEFORE claiming Connected. The public IP is stored in the service
and is the shared source for the Connect UI and foreground notice.
If the trace is blocked/unavailable, the local proxy remains running
but status is limited (Route ready / IP unverified). Rechecks can be
triggered manually or periodically. One successful trace does not
establish that every destination or UDP protocol will work.

Android switches traffic routes when VpnService.Builder.establish()
returns a TUN. KTest previously performed underlying-network metadata
operations before attaching its packet adapter; attachment now happens
immediately after establish. The metadata is set after forwarding begins.
This reduces the interruption introduced by KTest, not Android's
fundamental route transition.

KTest's own VPN becoming the default network was also capable of being
misidentified as a physical-network handover in its callback. The
callback ignores VPN transports and leaves revocation to VpnService.
Genuine Wi-Fi/cellular handovers still require serialized reconnect:
no guarantee of zero packet loss is made.

## Hardware acceptance gates

Test notification ID and cancellation on Android 10–16 and OEM builds,
permission denied/granted, proxy-only, system VPN, VPN-only Settings,
rapid connect/disconnect, manual Refresh, reconnect, process death and
onRevoke. Ensure the last notification disappears on final disconnect
and no orphan notification remains after an individual VPN stop.

Record the gap between route establishment and first successfully
forwarded packet, and compare before/after. Test both physical-network
handover and the single-TUN startup with packet captures. Ensure a
blocked Cloudflare trace leaves an honest limited state while allowing
healthy other destinations to function.

Sources:
https://developer.android.com/develop/connectivity/vpn
https://developer.android.com/reference/android/net/VpnService
https://developer.android.com/reference/android/app/Service
