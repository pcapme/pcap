package pcap

import (
	"fmt"
	"net"
	"testing"
)

func TestGetInterfaces(t *testing.T) {
	// No special privileges should be needed to call this.
	GetInterfaces()
}

func TestNetGetInterfaces(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.FailNow()
	}
	for _, iface := range interfaces {
		fmt.Printf("Interface: %+v\n", iface)
		addrs, _ := iface.Addrs()
		fmt.Printf("Addresses: %+v\n", addrs)
		maddrs, _ := iface.MulticastAddrs()
		fmt.Printf("Multicast addresses: %+v\n\n", maddrs)
	}
}
