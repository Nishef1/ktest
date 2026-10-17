//go:build windows

package main

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Read the native adapter snapshot rather than starting PowerShell. Never
// switch fingerprint algorithms on a timeout: that can misidentify one LAN
// as two networks. Failure disables cache reuse instead.
func networkFacts() []string {
	size := uint32(15000)
	for range 3 {
		if size == 0 || size > 4<<20 {
			return nil
		}
		buf := make([]byte, size)
		head := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, head, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil || size == 0 {
			return nil
		}
		var facts []string
		for a := head; a != nil; a = a.Next {
			name := strings.ToLower(windows.UTF16PtrToString(a.FriendlyName) + " " + windows.UTF16PtrToString(a.Description))
			if a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == windows.IF_TYPE_TUNNEL || a.FirstGatewayAddress == nil || strings.Contains(name, "ktest") || strings.Contains(name, "wintun") || strings.Contains(name, "windscribe") {
				continue
			}
			prefix := fmt.Sprintf("%s:%v:%s", windows.BytePtrToString(a.AdapterName), a.NetworkGuid, windows.UTF16PtrToString(a.DnsSuffix))
			for g := a.FirstGatewayAddress; g != nil; g = g.Next {
				facts = append(facts, prefix+":gateway:"+g.Address.IP().String())
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				facts = append(facts, prefix+":dns:"+d.Address.IP().String())
			}
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				// Ignore temporary IPv6 address rotation within the same LAN.
				if ip := u.Address.IP(); ip.To4() != nil {
					facts = append(facts, prefix+":ipv4:"+ip.String())
				}
			}
		}
		return facts
	}
	return nil
}
