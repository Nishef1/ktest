package aether

type Method struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func Methods() []Method {
	return []Method{
		{"auto", "Automatic (measured network order)"},
		{"masque-h2", "MASQUE HTTP/2 (TCP)"},
		{"masque-h3", "MASQUE HTTP/3 (QUIC/UDP)"},
		{"wireguard", "WireGuard"},
		{"gool-h2", "Gool: WireGuard inside MASQUE H2"},
		{"gool-h3", "Gool: WireGuard inside MASQUE H3"},
		{"wiw", "Classic WARP-in-WARP (WireGuard inside WireGuard)"},
		{"mim-h2", "MASQUE-in-MASQUE H2"},
		{"mim-h3", "MASQUE-in-MASQUE H3"},
		{"psiphon-warp", "Psiphon through WARP (Aether first)"},
		{"psiphon", "Psiphon only"},
		{"psiphon-cdn", "Psiphon CDN only"},
	}
}
