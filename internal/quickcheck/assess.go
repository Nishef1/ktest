package quickcheck

// Assessment describes whether the selected proxy adds observed website
// reachability beyond the machine's ordinary route. It is intentionally not
// a claim about the ISP, public egress IP, or censorship equipment.
type Assessment struct {
	Target string
	Kind   string // unavailable, proxy_regression, baseline_unknown, already_open, vpn_confounded, candidate
	Detail string
}

// Compare keeps same-target direct and SOCKS results separate, so a connected
// third-party VPN can never be counted as evidence for the selected technique.
func Compare(proxied, direct []Result, vpnSuspected bool) []Assessment {
	byTarget := make(map[string]Result, len(direct))
	for _, d := range direct {
		byTarget[d.Target] = d
	}
	out := make([]Assessment, 0, len(proxied))
	for _, p := range proxied {
		a := Assessment{Target: p.Target, Kind: "unavailable", Detail: p.Detail}
		baseline, checked := byTarget[p.Target]
		switch {
		case !p.Success && checked && baseline.Success:
			a.Kind = "proxy_regression"
			a.Detail = "direct access succeeds, but the selected ktest proxy fails: check its DNS and routing"
		case !p.Success:
			// The proxy could not access this particular target.
		case vpnSuspected:
			a.Kind = "vpn_confounded"
			a.Detail = "another VPN may be carrying traffic; cannot attribute reachability to ktest"
		case !checked:
			a.Kind = "baseline_unknown"
			a.Detail = "direct control did not finish; no attribution possible"
		case baseline.Success:
			a.Kind = "already_open"
			a.Detail = "this target was also reachable without the ktest proxy"
		default:
			a.Kind = "candidate"
			a.Detail = "only the proxy reached this target; verify with all other VPNs off"
		}
		out = append(out, a)
	}
	return out
}
