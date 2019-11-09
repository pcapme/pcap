package pcap

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// Bytes to save per-packet.
	DefaultSnapLen = 65535

	// Buffer size in megabytes.
	DefaultBufferSize = 8
)

type CaptureRequest struct {
	Filter     string
	Interfaces []string
}

func Capture(request CaptureRequest) error {
	handle, err := pcap.NewInactiveHandle(request.Interfaces[0])
	if err != nil {
		return err
	}
	fmt.Printf("Handle: %+v\n", handle)
	bpf, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, DefaultSnapLen, request.Filter)
	if err != nil {
		return err
	}
	fmt.Printf("BPF: %+v\n", bpf)
	defer handle.CleanUp()
	return nil
}

func GetInterfaces() ([]string, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		fmt.Printf("%+v\n", iface)
	}
	return nil, nil
}
