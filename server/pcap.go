package server

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

func StartCapture(ifname string, filter string, snaplen int) (*pcap.Handle, error) {
	if snaplen <= 0 {
		snaplen = DefaultSnapLen
	}
	inactiveHandle, err := pcap.NewInactiveHandle(ifname)
	if err != nil {
		return nil, err
	}
	err = inactiveHandle.SetSnapLen(snaplen)
	if err != nil {
		return nil, err
	}
	fmt.Printf("inactiveHandle: %+v\n", inactiveHandle)
	bpf, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, filter)
	if err != nil {
		fmt.Println("Error compiling BPF filter...")
		inactiveHandle.CleanUp()
		return nil, err
	}
	err = inactiveHandle.SetTimeout(pcap.BlockForever)
	if err != nil {
		fmt.Println("Error setting timeout...")
		inactiveHandle.CleanUp()
		return nil, err
	}
	var handle *pcap.Handle
	fmt.Println("Activating handle...")
	handle, err = inactiveHandle.Activate()
	fmt.Println("Handle activated!")
	if err != nil {
		return nil, err
	}
	err = handle.SetBPFInstructionFilter(bpf)
	if err != nil {
		handle.Close()
		return nil, err
	}
	return handle, err
}

func (ifcs *InterfaceCaptureState) readPackets() {
	for {
		data, ci, err := ifcs.handle.ZeroCopyReadPacketData()
		fmt.Printf("readPacket(): data=%+v ci=%+v\n", data, ci)
		if err != nil {
			fmt.Printf("ERROR - readPacket(): %+v", err)
			// XXX it seems weird to mutate the state here
			ifcs.err = err
			ifcs.state = Retrying
			ifcs.handle.Close()
			ifcs.handle = nil
			return
		}
	}
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
