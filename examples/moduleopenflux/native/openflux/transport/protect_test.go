package transport

import (
	"sync"
	"testing"
)

// TestBootstrapDNSServersConcurrent guards the AntiNet divergence documented
// on bootstrapDNSServers: the host replaces the resolver list inside a
// RUNNING helper on every network change, so SetBootstrapDNSServers overlaps
// the reads the shared/dns canon shim performs per lookup. Upstream's contract
// ("call it before starting a tunnel") has no equivalent moment here.
//
// Run with -race. Without the mutex this reports a data race on
// bootstrapDNSServers - and the failure mode is not a stale list but a torn
// slice header, i.e. a new pointer paired with a previous length.
func TestBootstrapDNSServersConcurrent(t *testing.T) {
	const rounds = 2000
	lists := [][]string{
		{"1.1.1.1"},
		{"8.8.8.8:53", "8.8.4.4:53"},
		{"192.168.1.1", "10.0.0.1:53", "77.88.8.8"},
		nil, // empty list restores the defaults
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			SetBootstrapDNSServers(lists[i%len(lists)])
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			for _, server := range BootstrapDNSServers() {
				if server == "" {
					t.Error("observed an empty resolver entry")
					return
				}
			}
		}
	}()

	wg.Wait()

	// Hand the package back in its default state for any other test.
	SetBootstrapDNSServers(nil)
}
