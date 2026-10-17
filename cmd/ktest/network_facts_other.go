//go:build !windows

package main

import (
	"net"
	"strings"
)

func networkFacts() []string {
	var facts []string
	nics, _ := net.Interfaces()
	for _, nic := range nics {
		if nic.Flags&net.FlagUp == 0 || nic.Flags&net.FlagLoopback != 0 || strings.Contains(strings.ToLower(nic.Name), "tun") {
			continue
		}
		addrs, _ := nic.Addrs()
		for _, addr := range addrs {
			facts = append(facts, nic.Name+":"+nic.HardwareAddr.String()+":"+addr.String())
		}
	}
	return facts
}
