package tlsshape

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A calibration that reached the gateway is good for hours; one that reached
// nothing (offline, or every hello refused) is asked again soon.
const (
	CacheTTL       = 6 * time.Hour
	FailedCacheTTL = 10 * time.Minute
)

type cacheFile struct {
	Version  int               `json:"version"`
	Networks map[string]Result `json:"networks"`
}

var cacheMu sync.Mutex

// Cached returns the fresh calibration of a network for these options.
func Cached(path, network string, o Options) (Result, bool) {
	if path == "" || network == "" {
		return Result{}, false
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	c := readCache(path)
	r, ok := c.Networks[network]
	if !ok || r.Options != o.Key() || time.Until(r.Checked) > time.Minute {
		return Result{}, false
	}
	ttl := CacheTTL
	if !r.Reached() {
		ttl = FailedCacheTTL
	}
	if time.Since(r.Checked) > ttl {
		return Result{}, false
	}
	return r, true
}

// Save stores a calibration, keeping the 16 most recent networks.
func Save(path, network string, r Result) error {
	if path == "" || network == "" {
		return errors.New("no calibration cache")
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	c := readCache(path)
	c.Networks[network] = r
	for len(c.Networks) > 16 {
		oldest, at := "", time.Time{}
		for k, v := range c.Networks {
			if k != network && (oldest == "" || v.Checked.Before(at)) {
				oldest, at = k, v.Checked
			}
		}
		delete(c.Networks, oldest)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tls-calibration-*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	return os.Rename(tmp.Name(), path)
}

func readCache(path string) cacheFile {
	c := cacheFile{Version: 1, Networks: map[string]Result{}}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 1<<20 {
		return c
	}
	var read cacheFile
	if json.Unmarshal(data, &read) == nil && read.Version == 1 && read.Networks != nil {
		return read
	}
	return c
}

// Ensure returns this network's calibration for the options, measuring it
// when the cached one is missing or stale. Nothing is measured when every
// choice is fixed to one value, and a cancelled measurement is not saved.
func Ensure(ctx context.Context, path, network string, o Options, c Config) (Result, bool) {
	if r, ok := Cached(path, network, o); ok {
		return r, true
	}
	if o.Fingerprint != Auto && o.Fragment != Auto && o.SNI != Auto && !strings.Contains(o.SNI, ",") {
		return Result{}, false
	}
	r := Calibrate(ctx, o, c)
	if ctx.Err() != nil && !r.Reached() {
		return Result{}, false
	}
	_ = Save(path, network, r)
	return r, true
}
