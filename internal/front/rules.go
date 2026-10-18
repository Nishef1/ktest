package front

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

// Front is one way to reach a family: which server name to show on the wire
// and which machine to connect to.
type Front struct {
	// SNI is the server name sent in the ClientHello. Empty sends none.
	SNI string
	// Dial is the name whose address is connected to. Empty means the address
	// of the site itself (what the application asked for).
	Dial string
	// ECH, when set, is the public name of an Encrypted Client Hello service
	// (Cloudflare's is cloudflare-ech.com): the wire shows that name and the real
	// one travels encrypted. SNI is then unused.
	ECH string
}

func (f Front) String() string {
	if f.ECH != "" {
		if f.Dial == "" {
			return "ECH (" + f.ECH + ")"
		}
		return "ECH (" + f.ECH + ") @ " + f.Dial
	}
	sni := f.SNI
	if sni == "" {
		sni = "no SNI"
	}
	if f.Dial == "" {
		return sni
	}
	return sni + " @ " + f.Dial
}

// Family is a group of sites that one CDN edge serves regardless of the server
// name in the ClientHello. That is the property domain fronting relies on: the
// name on the wire (what a censor reads) and the name in the request (what the
// edge routes by) may differ.
type Family struct {
	Name string
	// Domains are covered with their subdomains.
	Domains []string
	Fronts  []Front
	// Verify are names the edge's certificate may be valid for, besides the
	// front's SNI and the site itself. Fronting to an edge that answers with its
	// default certificate cannot be verified against the requested name.
	Verify []string
	// H1Only are domains whose traffic must stay on HTTP/1.1 through the front.
	H1Only []string
	// Hints are edge addresses used only when no trusted address for the site
	// can be had (system DNS poisoned, encrypted DNS filtered). Any address of
	// the family's edge serves every site of the family, so a stale hint still
	// works as long as it is an edge address at all.
	Hints []string
	// NoStandIn are domains that only their own servers can serve: a front that
	// dials another machine (the www.google.com stand-in) would connect, verify
	// and then answer 404, which looks like success and hides the real failure.
	NoStandIn []string
}

// Match reports whether host belongs to the family.
func (f *Family) Match(host string) bool {
	host = normalize(host)
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	for _, d := range f.Domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func (f *Family) h1Only(host string) bool {
	host = normalize(host)
	for _, d := range f.H1Only {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func (f *Family) noStandIn(host string) bool {
	host = normalize(host)
	for _, d := range f.NoStandIn {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func normalize(h string) string { return strings.ToLower(strings.TrimSuffix(h, ".")) }

// DefaultFamilies is the built-in table. It is derived from what the public
// MITM-DomainFronting project and its issue tracker report as working for
// Iranian networks (Google, Meta and Fastly-hosted sites) and from direct tests
// of the Google edge. The SNI choices are the part that goes stale: a name
// that is open on one operator is closed on the next (the project's python.org
// vs pypi.org story), so every family lists several and ktest learns which
// one the current network lets through. profiles/fronts.txt can add more.
func DefaultFamilies() []Family {
	return []Family{
		{
			Name: "google",
			Domains: []string{
				"google.com", "youtube.com", "youtu.be", "youtube-nocookie.com", "ytimg.com",
				"ggpht.com", "googlevideo.com", "gstatic.com", "googleapis.com",
				"googleusercontent.com", "gvt1.com", "gvt2.com", "android.com",
				"gmail.com", "googlemail.com", "withgoogle.com",
			},
			Fronts: []Front{
				{SNI: "www.google.com"},
				{SNI: "www.google.com", Dial: "www.google.com"},
				{SNI: "www.gstatic.com", Dial: "www.google.com"},
				{SNI: "www.googleapis.com", Dial: "www.google.com"},
			},
			Verify: []string{"www.google.com", "www.youtube.com", "www.googlevideo.com", "www.gstatic.com", "www.googleapis.com", "dns.google"},
			// The video servers were kept on HTTP/1.1 in the reference project.
			H1Only: []string{"googlevideo.com"},
			// Video comes from cache servers, not from the front ends.
			NoStandIn: []string{"googlevideo.com"},
		},
		{
			Name: "meta",
			Domains: []string{
				"facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "instagram.com", "cdninstagram.com",
				"whatsapp.com", "whatsapp.net", "meta.com", "messenger.com", "threads.net", "threads.com", "oculus.com",
			},
			Fronts: []Front{
				{SNI: "www.microsoft.com"},
				{SNI: ""},
				{SNI: "www.microsoft.com", Dial: "www.facebook.com"},
			},
			Hints: []string{"57.144.194.34", "57.144.200.1", "57.144.194.141"},
			Verify: []string{
				"www.facebook.com", "www.instagram.com", "www.whatsapp.com", "www.whatsapp.net", "www.fb.com",
				"www.meta.com", "www.messenger.com", "www.fbcdn.net", "www.cdninstagram.com", "www.oculus.com",
			},
		},
		{
			// Fastly serves X's static files, photos and video on customer-specific
			// addresses, so the site's own address (or these hints) is needed;
			// the edge answers with its *.twimg.com certificate whatever the SNI is.
			Name:    "twimg",
			Domains: []string{"abs.twimg.com", "abs-0.twimg.com", "pbs.twimg.com", "video.twimg.com", "ton.twimg.com"},
			Fronts:  []Front{{SNI: "pypi.org"}, {SNI: "www.python.org"}},
			Hints:   []string{"146.75.104.159", "146.75.104.158"},
			Verify:  []string{"twimg.com", "abs.twimg.com"},
			// Photo transfers on these edges can stall mid-body over HTTP/2.
			H1Only: []string{"pbs.twimg.com"},
		},
		{
			// Cloudflare refuses a request whose Host differs from the SNI, so plain
			// fronting is impossible here. Encrypted Client Hello hides the real name
			// instead. Any Cloudflare address serves any Cloudflare site, so the hints
			// make this work without any DNS.
			Name: "cloudflare",
			Domains: []string{
				"x.com", "twitter.com", "t.co", "twimg.com", "discord.com", "discord.gg",
				"discordapp.com", "medium.com", "npmjs.com",
			},
			Fronts: []Front{{ECH: CloudflareECH}},
			Hints:  []string{"162.159.140.229", "172.66.0.227", "188.114.99.0", "172.66.157.237", "104.18.37.127"},
		},
		{
			Name: "fastly",
			Domains: []string{
				"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "redditspace.com",
				"redditinc.com", "redditblog.com", "reddithelp.com", "cnn.com", "cnn.io", "buzzfeed.com",
				"pypi.org", "pythonhosted.org", "python.org", "flathub.org",
			},
			Fronts: []Front{
				{SNI: "pypi.org", Dial: "pypi.org"},
				{SNI: "www.python.org", Dial: "www.python.org"},
				{SNI: "github.githubassets.com", Dial: "github.githubassets.com"},
			},
			Verify: []string{
				"www.python.org", "pypi.org", "fastly.com", "www.fastly.com", "developer.fastly.com",
				"reddit.com", "www.reddit.com", "githubassets.com", "github.githubassets.com", "github.com",
				"githubusercontent.com", "files.pythonhosted.org",
			},
		},
	}
}

// CloudflareECH is the public name Cloudflare's Encrypted Client Hello uses.
const CloudflareECH = "cloudflare-ech.com"

// PermittedDomains is what the CA's name constraints are built from.
func PermittedDomains(fams []Family) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fams {
		for _, d := range f.Domains {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// Lookup returns the first family that covers host, or nil.
func Lookup(fams []Family, host string) *Family {
	for i := range fams {
		if fams[i].Match(host) {
			return &fams[i]
		}
	}
	return nil
}

// LookupAll returns every family that covers host: a site such as twimg.com is
// served by more than one CDN, and each has its own way in.
func LookupAll(fams []Family, host string) []*Family {
	var out []*Family
	for i := range fams {
		if fams[i].Match(host) {
			out = append(out, &fams[i])
		}
	}
	return out
}

// Uncovered lists the domains of fams that a CA's constraints do not permit,
// which is what a CA created by an older ktest looks like.
func Uncovered(fams []Family, permitted []string) []string {
	have := map[string]bool{}
	for _, p := range permitted {
		have[p] = true
	}
	var out []string
	for _, d := range PermittedDomains(fams) {
		if !have[d] {
			out = append(out, d)
		}
	}
	return out
}

// ParseFronts reads user-supplied fronts, one per line:
//
//	family  sni  [dial]
//
// sni "-" sends no server name; dial "@own" (or an omitted third column with
// sni "-") connects to the site's own address, otherwise an omitted dial means
// the sni's own address. They are tried before the built-in ones. This is the
// file to edit when a name stops working on your operator.
func ParseFronts(text string) (map[string][]Front, error) {
	out := map[string][]Front{}
	sc := bufio.NewScanner(strings.NewReader(text))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		cols := strings.Fields(line)
		if len(cols) < 2 || len(cols) > 3 {
			return nil, fmt.Errorf("line %d: want \"family sni [dial]\"", n)
		}
		fr := Front{SNI: strings.ToLower(cols[1])}
		if fr.SNI == "-" {
			fr.SNI = ""
		}
		switch {
		case len(cols) == 3 && cols[2] == "@own":
		case len(cols) == 3:
			fr.Dial = strings.ToLower(cols[2])
		default:
			fr.Dial = fr.SNI
		}
		out[strings.ToLower(cols[0])] = append(out[strings.ToLower(cols[0])], fr)
	}
	return out, sc.Err()
}

// WithFronts puts extra fronts ahead of each family's built-in ones.
func WithFronts(fams []Family, extra map[string][]Front) []Family {
	out := make([]Family, len(fams))
	copy(out, fams)
	for i := range out {
		if more := extra[out[i].Name]; len(more) > 0 {
			out[i].Fronts = append(append([]Front(nil), more...), out[i].Fronts...)
		}
	}
	return out
}
