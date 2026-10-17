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
	"sync"
	"time"
)

const wsCatalogMaxAge = 24 * time.Hour
const wsCatalogLimit = 4 << 20

// These are public provider lists, not account/session APIs. The regional
// response can contain anti-censorship addresses absent from the global list.
var wsCatalogURLs = []struct{ name, url string }{
	{"global", "https://assets.windscribe.com/serverlist/openvpn/1/ktest?country_override=ZZ"},
	{"regional", "https://assets.windscribe.com/serverlist/openvpn/1/ktest"},
}

type wsNode struct {
	IP       string `json:"ip"`
	TCP      string `json:"ip2"`
	IP3      string `json:"ip3"`
	Hostname string `json:"hostname"`
	Group    string `json:"group"`
}

type wsCatalogList struct {
	Fetched time.Time       `json:"fetched"`
	Body    json.RawMessage `json:"body"`
	nodes   map[string]wsNode
}

type wsEndpoint struct{ ip, source string }

type wsNodeCatalog struct {
	mu    sync.RWMutex
	lists map[string]wsCatalogList
	ready chan struct{}
}

func newWSNodeCatalog() *wsNodeCatalog {
	return &wsNodeCatalog{lists: make(map[string]wsCatalogList), ready: make(chan struct{})}
}

func publicWSIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func parseWSNodes(body []byte) (map[string]wsNode, error) {
	var response struct {
		Data []struct {
			Nodes []wsNode `json:"nodes"`
		} `json:"data"`
	}
	if len(body) > wsCatalogLimit {
		return nil, errors.New("Windscribe node list exceeds size limit")
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	nodes := make(map[string]wsNode)
	for _, country := range response.Data {
		for _, node := range country.Nodes {
			if !publicWSIP(node.TCP) || !publicWSIP(node.IP) || !publicWSIP(node.IP3) || !validHostname(node.Hostname) {
				return nil, errors.New("Windscribe node list contains an invalid address or hostname")
			}
			if prev, ok := nodes[node.TCP]; ok && prev != node {
				return nil, fmt.Errorf("ambiguous Windscribe TCP node %s", node.TCP)
			}
			nodes[node.TCP] = node
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
	return nil
}

// endpoints matches the exact TCP IP. Only addresses advertised for that same
// node are candidates; no neighbouring IP or different location is invented.
// WStunnel may test both provider-advertised alternates because its current
// authenticated PortMap is unavailable here. Stealth is restricted to ip3
// later in carriersFor, as specified in Windscribe's published port map.
func (c *wsNodeCatalog) endpoints(tcp string) []wsEndpoint {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var result []wsEndpoint
	seen := map[string]bool{tcp: true}
	hostname := ""
	for _, source := range wsCatalogURLs {
		list, ok := c.lists[source.name]
		if !ok || time.Since(list.Fetched) > wsCatalogMaxAge || time.Until(list.Fetched) > 5*time.Minute {
			continue
		}
		node, ok := list.nodes[tcp]
		if !ok {
			continue
		}
		if hostname != "" && node.Hostname != hostname {
			return nil // conflicting snapshots must not mix two nodes
		}
		hostname = node.Hostname
		for _, alt := range []struct{ ip, field string }{{node.IP, "ip"}, {node.IP3, "ip3"}} {
			if !seen[alt.ip] {
				seen[alt.ip] = true
				result = append(result, wsEndpoint{alt.ip, source.name + "/" + alt.field})
			}
		}
	}
	return result
}

// endpointsByField preserves the provider's protocol-specific endpoint role.
// A node can advertise the same IP for ip and ip3; deduplicating solely by
// address would erase the Stealth ip3 route even though it is valid.
func (c *wsNodeCatalog) endpointsByField(tcp, field string) []wsEndpoint {
	if c == nil || field != "ip3" {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	seen := make(map[string]bool)
	var result []wsEndpoint
	hostname := ""
	for _, source := range wsCatalogURLs {
		list, ok := c.lists[source.name]
		if !ok || time.Since(list.Fetched) > wsCatalogMaxAge || time.Until(list.Fetched) > 5*time.Minute {
			continue
		}
		node, ok := list.nodes[tcp]
		if !ok {
			continue
		}
		if hostname != "" && hostname != node.Hostname {
			return nil
		}
		hostname = node.Hostname
		if !seen[node.IP3] {
			seen[node.IP3] = true
			result = append(result, wsEndpoint{node.IP3, source.name + "/ip3"})
		}
	}
	return result
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

func (c *wsNodeCatalog) refresh(ctx context.Context, client *http.Client, path string, logf func(string, ...any)) bool {
	var wg sync.WaitGroup
	updated := make(chan struct{}, len(wsCatalogURLs))
	for _, source := range wsCatalogURLs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, err := fetchWSNodeList(ctx, client, source.url)
			if err == nil {
				err = c.replace(source.name, body, time.Now())
			}
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
	close(c.ready)
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
