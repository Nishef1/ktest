package mobilebridge

import "errors"

// windscribeHTTPAddress is fixed because the OpenVPN profile's
// "http-proxy 127.0.0.1 <port>" line is written once by the user.
var windscribeHTTPAddress = "127.0.0.1:18118"

// launchLocalCores is replaced in tests; the packaged ByeDPI is hash-pinned.
var launchLocalCores = launchAndroidLocalCores

// WindscribeHTTPProxy is the loopback HTTP proxy that an OpenVPN for Android
// profile names in its http-proxy line while Windscribe mode is connected.
func WindscribeHTTPProxy() string {
	return windscribeHTTPAddress
}

// StartAndroidWindscribeProxy starts the proxy-only Windscribe bridge. Android
// has no Windscribe app upstream setting, so a Windscribe OpenVPN TCP profile
// in OpenVPN for Android uses this HTTP proxy. Only the packaged ByeDPI cores
// and the built-in ClientHello cuts are offered: no exits, fronting, plain
// TCP or VpnService.
func StartAndroidWindscribeProxy(nativeLibraryDir string) (string, error) {
	if nativeLibraryDir == "" {
		return "", errors.New("packaged ByeDPI directory is required")
	}
	return startProxy("windscribe", "", nil, nativeLibraryDir)
}
