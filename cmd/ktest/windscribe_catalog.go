package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const wsCatalogMaxAge = 24 * time.Hour
const wsCatalogLimit = 4 << 20

// Windscribe desktop switched to the mob-v2 server list in 2026.
// The older openvpn URLs are fallbacks on networks that cannot reach the
// current API. The two mob-v2 variants may contain different node subsets.
// Timestamp suffixes match the public API format; no account tokens are sent.
type wsCatalogSource struct {
	name, url, fallback string
}

var wsCatalogURLs = []wsCatalogSource{
	{"global", "https://assets.windscribe.com/serverlist/mob-v2/1/", "https://assets.windscribe.com/serverlist/openvpn/1/ktest?country_override=ZZ"},
	{"regional", "https://assets.windscribe.com/serverlist/mob-v2/0/", "https://assets.windscribe.com/serverlist/openvpn/1/ktest"},
}

type wsNode struct {
	IP              string `json:"ip"`
	TCP             string `json:"ip2"`
	IP3             string `json:"ip3"`
	Hostname        string `json:"hostname"`
	Group           string `json:"group"`
	Country         string `json:"-"`  // provider location label, never IP geolocation
	ForceDisconnect int    `json:"fd"` // 1: draining node; no new sessions
}

type wsCatalogList struct {
	Fetched time.Time       `json:"fetched"`
	Body    json.RawMessage `json:"body"`
	nodes   map[string]wsNode
}

type wsEndpoint struct{ ip, source string }

type wsNodeCatalog struct {
	mu        sync.RWMutex
	lists     map[string]wsCatalogList
	ready     chan struct{}
	readyOnce sync.Once
	changed   chan struct{} // broadcast on provider updates and finished fetches
	fetching  int
}

func newWSNodeCatalog() *wsNodeCatalog {
	return &wsNodeCatalog{lists: make(map[string]wsCatalogList), ready: make(chan struct{}), changed: make(chan struct{})}
}

// A cached or newly fetched *valid* source unblocks OpenVPN carrier discovery.
// Do not wait for a second, inaccessible source to time out before using it.
func (c *wsNodeCatalog) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *wsNodeCatalog) beginFetch() {
	c.mu.Lock()
	if c.fetching == 0 {
		c.fetching = len(wsCatalogURLs)
		c.notifyLocked()
	}
	c.mu.Unlock()
}

func (c *wsNodeCatalog) finishFetch() {
	c.mu.Lock()
	if c.fetching > 0 {
		c.fetching--
		c.notifyLocked()
	}
	c.mu.Unlock()
}

func (c *wsNodeCatalog) waitForTarget(ctx context.Context, tcp string, budget time.Duration) bool {
	timer := time.NewTimer(budget)
	defer timer.Stop()
	for {
		c.mu.RLock()
		pending, changed := c.fetching > 0, c.changed
		c.mu.RUnlock()
		if len(c.endpoints(tcp)) > 0 {
			return true
		}
		if !pending {
			return false
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		}
	}
}

func (c *wsNodeCatalog) signalReady() {
	c.readyOnce.Do(func() { close(c.ready) })
}

func publicWSIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func parseWSNodes(body []byte) (map[string]wsNode, error) {
	var response struct {
		Data []struct {
			Name   string   `json:"name"`
			Nodes  []wsNode `json:"nodes"`
			Groups []struct {
				City  string   `json:"city"`
				Nick  string   `json:"nick"`
				Nodes []wsNode `json:"nodes"`
			} `json:"groups"`
		} `json:"data"`
	}
	if len(body) > wsCatalogLimit {
		return nil, errors.New("Windscribe node list exceeds size limit")
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	nodes := make(map[string]wsNode)
	addNodes := func(list []wsNode, country, group string) error {
		for _, node := range list {
			node.Country = country
			if node.Group == "" {
				node.Group = group
			}
			// Windscribe wsnet 1.5.33 treats fd:1 as a draining
			// server; dialing it can fail even when nearby nodes work.
			if node.ForceDisconnect == 1 {
				continue
			}
			// The official wsnet InventoryParser permits null ip3. Such a
			// node is still valid for raw OpenVPN; it simply has no Stealth
			// endpoint. Skip isolated malformed nodes instead of discarding
			// every valid node in a provider snapshot.
			if !publicWSIP(node.TCP) || !publicWSIP(node.IP) ||
				(node.IP3 != "" && !publicWSIP(node.IP3)) || !validHostname(node.Hostname) {
				continue
			}
			if prev, ok := nodes[node.TCP]; ok && prev != node {
				return fmt.Errorf("ambiguous Windscribe TCP node %s", node.TCP)
			}
			nodes[node.TCP] = node
		}
		return nil
	}
	for _, country := range response.Data {
		// Older serverlist/openvpn responses place nodes directly in each
		// country; current mob-v2 responses place them under groups[].nodes.
		if err := addNodes(country.Nodes, country.Name, ""); err != nil {
			return nil, err
		}
		for _, group := range country.Groups {
			label := group.City
			if group.Nick != "" {
				if label != "" {
					label += " - "
				}
				label += group.Nick
			}
			if err := addNodes(group.Nodes, country.Name, label); err != nil {
				return nil, err
			}
		}
	}
	if len(nodes) == 0 {
		return nil, errors.New("Windscribe node list is empty")
	}
	return nodes, nil
}

func (c *wsNodeCatalog) replace(source string, body []byte, fetched time.Time) error {
	nodes, err := parseWSNodes(body)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lists[source] = wsCatalogList{Fetched: fetched, Body: append(json.RawMessage(nil), body...), nodes: nodes}
	c.notifyLocked()
	c.signalReady()
	return nil
}

// endpoints matches the exact TCP IP. Only addresses advertised for that same
// node are candidates; no neighbouring IP or different location is invented.
// WStunnel may test both provider-advertised alternates because its current
// authenticated PortMap is unavailable here. Stealth is restricted to ip3
// later in carriersFor, as specified in Windscribe's published port map.
type wsCatalogMatch struct {
	node   wsNode
	source string
}

// Never join fields belonging to conflicting provider node identities.
// A newer valid source may independently supply a usable alternate for the
// requested exact OpenVPN TCP destination.
func (c *wsNodeCatalog) matches(tcp string) []wsCatalogMatch {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var newest time.Time
	var identity string
	for _, source := range wsCatalogURLs {
		list, ok := c.lists[source.name]
		if !ok || time.Since(list.Fetched) > wsCatalogMaxAge || time.Until(list.Fetched) > 5*time.Minute {
			continue
		}
		node, ok := list.nodes[tcp]
		if ok && (identity == "" || list.Fetched.After(newest)) {
			identity, newest = node.Hostname, list.Fetched
		}
	}
	if identity == "" {
		return nil
	}
	var result []wsCatalogMatch
	for _, source := range wsCatalogURLs {
		list, ok := c.lists[source.name]
		if !ok || time.Since(list.Fetched) > wsCatalogMaxAge || time.Until(list.Fetched) > 5*time.Minute {
			continue
		}
		node, ok := list.nodes[tcp]
		if ok && node.Hostname == identity {
			result = append(result, wsCatalogMatch{node: node, source: source.name})
		}
	}
	return result
}

func (c *wsNodeCatalog) endpoints(tcp string) []wsEndpoint {
	seen := map[string]bool{tcp: true}
	var result []wsEndpoint
	for _, match := range c.matches(tcp) {
		for _, alt := range []struct{ ip, field string }{{match.node.IP, "ip"}, {match.node.IP3, "ip3"}} {
			if alt.ip != "" && !seen[alt.ip] {
				seen[alt.ip] = true
				result = append(result, wsEndpoint{alt.ip, match.source + "/" + alt.field})
			}
		}
	}
	return result
}

func (c *wsNodeCatalog) endpointsByField(tcp, field string) []wsEndpoint {
	if field != "ip3" {
		return nil
	}
	seen := make(map[string]bool)
	var result []wsEndpoint
	for _, match := range c.matches(tcp) {
		if ip := match.node.IP3; ip != "" && !seen[ip] {
			seen[ip] = true
			result = append(result, wsEndpoint{ip, match.source + "/ip3"})
		}
	}
	return result
}

func (c *wsNodeCatalog) missingReason(tcp string) string {
	if c == nil {
		return "catalog disabled"
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var fresh int
	for _, source := range wsCatalogURLs {
		list, ok := c.lists[source.name]
		if !ok || time.Since(list.Fetched) > wsCatalogMaxAge || time.Until(list.Fetched) > 5*time.Minute {
			continue
		}
		fresh++
		if _, found := list.nodes[tcp]; found {
			return "node found but no eligible alternate endpoint"
		}
	}
	if c.fetching > 0 {
		return "catalog still fetching requested node"
	}
	if fresh == 0 {
		return "catalog missing or expired"
	}
	return fmt.Sprintf("node not found in %d fresh provider source(s)", fresh)
}

func (c *wsNodeCatalog) load(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var lists map[string]wsCatalogList
	if json.NewDecoder(io.LimitReader(f, 3*wsCatalogLimit)).Decode(&lists) != nil {
		return
	}
	for _, source := range wsCatalogURLs {
		if list, ok := lists[source.name]; ok && time.Since(list.Fetched) <= wsCatalogMaxAge && time.Until(list.Fetched) <= 5*time.Minute {
			_ = c.replace(source.name, list.Body, list.Fetched)
		}
	}
}

func (c *wsNodeCatalog) save(path string) error {
	c.mu.RLock()
	body, err := json.Marshal(c.lists)
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "windscribe-nodes-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(body)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}

func fetchWSNodeList(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, wsCatalogLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > wsCatalogLimit {
		return nil, errors.New("Windscribe node list exceeds size limit")
	}
	return body, nil
}

// mob-v2 uses a Unix-time URL component. A source without trailing slash
// stays unchanged, allowing local regression servers to exercise fallbacks.
func wsCatalogRequestURL(base string, now time.Time) string {
	if strings.HasSuffix(base, "/") {
		return base + strconv.FormatInt(now.Unix(), 10)
	}
	return base
}

func (c *wsNodeCatalog) updateFromSource(ctx context.Context, client *http.Client, source wsCatalogSource) error {
	urls := []string{wsCatalogRequestURL(source.url, time.Now()), source.fallback}
	var lastErr error
	for _, url := range urls {
		if url == "" {
			continue
		}
		body, err := fetchWSNodeList(ctx, client, url)
		if err == nil {
			err = c.replace(source.name, body, time.Now())
		}
		if err == nil {
			return nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if lastErr == nil {
		return errors.New("Windscribe catalog has no usable endpoints")
	}
	return lastErr
}

func (c *wsNodeCatalog) refresh(ctx context.Context, client *http.Client, path string, logf func(string, ...any)) bool {
	c.beginFetch()
	var wg sync.WaitGroup
	updated := make(chan struct{}, len(wsCatalogURLs))
	for _, source := range wsCatalogURLs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.finishFetch()
			err := c.updateFromSource(ctx, client, source)
			if err != nil {
				logf("Windscribe node list %s unavailable: %v; retaining fresh cache", source.name, err)
			} else {
				updated <- struct{}{}
				logf("Windscribe node list %s refreshed from provider", source.name)
			}
		}()
	}
	wg.Wait()
	if err := c.save(path); err != nil {
		logf("Windscribe node cache: %v", err)
	}
	return len(updated) == len(wsCatalogURLs)
}

func (c *wsNodeCatalog) run(ctx context.Context, client *http.Client, path string, logf func(string, ...any)) {
	refreshed := c.refresh(ctx, client, path, logf)
	c.signalReady() // no source succeeded: unblock with explicit missing mapping
	for {
		delay := 30 * time.Minute
		if !refreshed {
			delay = 30 * time.Second // bootstrap paths may become ready after startup
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			refreshed = c.refresh(ctx, client, path, logf)
		}
	}
}
