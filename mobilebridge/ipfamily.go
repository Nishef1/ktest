package mobilebridge

import (
	"errors"
	"sync"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

var destinationFamilyMu sync.Mutex
var destinationFamily = "both"

// SetDestinationFamily applies to the next connection only. A running
// session keeps its immutable policy; Android calls this before startup.
func SetDestinationFamily(family string) error {
	if family == "" || !smartproxy.ValidDestinationFamily(family) {
		return errors.New("destination family must be ipv4, both or ipv6")
	}
	destinationFamilyMu.Lock()
	defer destinationFamilyMu.Unlock()
	destinationFamily = family
	return nil
}

func currentDestinationFamily() string {
	destinationFamilyMu.Lock()
	defer destinationFamilyMu.Unlock()
	return destinationFamily
}
