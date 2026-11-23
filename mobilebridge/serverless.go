package mobilebridge

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/Nishef1/ktest/internal/xraycfg"
)

// ServerlessMethodCatalog is an independent method inventory. It is not an
// Aether/Psiphon profile or an authenticated foreign exit.
func ServerlessMethodCatalog() string {
	return `{"methods":[{"id":"A","title":"Fragment A"},{"id":"B","title":"Fragment B"},{"id":"OOB","title":"Out-of-band (OOB)"}]}`
}

// ServerlessAssetsValid lets Kotlin copy the signed APK geo data only when
// the private copies are missing or corrupted. No network access is involved.
func ServerlessAssetsValid(dir string) bool {
	return xraycfg.VerifyAndroidServerlessAssets(dir) == nil
}

// StartAndroidServerlessProxy exposes a standalone, user-selected direct ISP
// strategy through the same stable local Go SOCKS/HTTP listeners. Never
// substitutes Serverless for a foreign exit or silently starts the device VPN.
func StartAndroidServerlessProxy(variant, nativeDir, privateDir string) (string, error) {
	variant = strings.ToUpper(strings.TrimSpace(variant))
	if variant != "A" && variant != "B" && variant != "OOB" {
		return "", errors.New("Serverless method must be A, B or OOB")
	}
	if !realPrivateDirectory(privateDir) || !filepath.IsAbs(nativeDir) {
		return "", errors.New("Serverless requires app-private files and packaged native Xray")
	}
	return startProxyConfigured(context.Background(), "serverless", variant, nil, nativeDir, "", privateDir, false)
}
