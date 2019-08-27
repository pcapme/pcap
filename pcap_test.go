package pcap

import "testing"

func TestGetInterfaces(t *testing.T) {
	// No special privileges should be needed to call this.
	GetInterfaces()
}
