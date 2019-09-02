package pcap

import (
	"context"
	"github.com/google/gopacket/pcap"
	"github.com/mpontillo/pcap/api"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

type server struct{}

func (s *server) Init(ctx context.Context, in *api.InitRequest) (*api.InitReply, error) {
	log.Printf("Init(%+v)", in)
	log.Printf("GetOptionalFilter() = %+v", in.GetOptionalFilter())
	filter := in.GetFilter()
	log.Printf("GetFilter() = %+v", filter)
	err := Capture(CaptureRequest{Filter: filter, Interfaces: in.GetInterfaces()})
	return &api.InitReply{
		Success: err == nil,
	}, nil
}

func (s *server) InterfaceList(ctx context.Context, in *api.InterfaceListRequest) (*api.InterfaceListReply, error) {
	log.Printf("InterfaceList(%+v)", in)
	result := &api.InterfaceListReply{
		Success: false,
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return result, nil
	}
	resultInterfaces := make([]*api.Interface, 0, len(interfaces))
	for _, iface := range interfaces {
		isUp := iface.Flags&unix.IFF_UP != 0
		if !(isUp || in.All) {
			// Skip the interface if it it's UP, or if --all wasn't specified.
			continue
		}
		resultInterface := &api.Interface{Name: iface.Name, Up: isUp}
		resultInterface.EthernetAddresses = make([]*api.Address, 0, 8)
		resultInterface.Ipv4Addresses = make([]*api.Address, 0, 8)
		resultInterface.Ipv6Addresses = make([]*api.Address, 0, 8)
		resultInterface.EthernetAddresses = append(
			resultInterface.EthernetAddresses,
			&api.Address{
				Value: iface.HardwareAddr.String(),
			})
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			address := strings.Split(addr.String(), "/")[0]
			ip := net.ParseIP(address)
			if ip.To4() != nil {
				log.Printf("[4] [%s] ip: %+v\n", addr.String(), ip)
				// Found an IPv4 address.
				resultInterface.Ipv4Addresses = append(
					resultInterface.Ipv4Addresses,
					&api.Address{
						Value: address,
					})
			} else {
				log.Printf("[6] [%s] ip: %+v\n", addr.String(), ip)
				// Found an IPv6 address.
				resultInterface.Ipv6Addresses = append(
					resultInterface.Ipv6Addresses,
					&api.Address{
						Value: address,
					})
			}
		}
		resultInterfaces = append(resultInterfaces, resultInterface)
	}
	result.Success = true
	result.Interfaces = resultInterfaces
	return result, nil
}

func (s *server) LiveCapture(in *api.CaptureRequest, stream api.PCAP_LiveCaptureServer) error {
	inactiveHandle, err := pcap.NewInactiveHandle(in.Interface)
	defer inactiveHandle.CleanUp()
	if err != nil {
		return err
	}
	err = inactiveHandle.SetImmediateMode(in.ImmediateMode)
	if err != nil {
		return err
	}
	err = inactiveHandle.SetBufferSize(1024 * 1024 * 4096)
	if err != nil {
		return err
	}
	err = inactiveHandle.SetPromisc(false)
	if err != nil {
		return err
	}
	handle, err := inactiveHandle.Activate()
	defer handle.Close()
	if err != nil {
		return err
	}
	for {
		data, captureInfo, err := handle.ReadPacketData()
		if err != nil {
			return err
		}
		packetData := &api.PacketData{
			Seconds:              uint32(captureInfo.Timestamp.Second()),
			Microseconds:         uint32(captureInfo.Timestamp.Nanosecond()) * 1000,
			OriginalLength:       uint32(captureInfo.Length),
			Data:                 data,
		}
		err = stream.Send(&api.CaptureReply{
			ReplyData: &api.CaptureReply_Data{Data: packetData},
		})
		if err != nil {
			return err
		}
	}
}

func registerSigQuitHandler() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGQUIT)
	buf := make([]byte, 1<<20)
	for {
		<-sigs
		stacklen := runtime.Stack(buf, true)
		log.Printf("=== received SIGQUIT ===\n*** goroutine dump...\n%s\n*** end\n", buf[:stacklen])
	}
}

func StartUnixSocketServer() {
	go registerSigQuitHandler()
	listener, err := net.Listen("unix", DefaultSocketPath)
	if err != nil {
		log.Fatalf("Failed to Listen(): %v", err)
	}
	s := grpc.NewServer()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	context.WithCancel(context.Background())
	go func() {
		<-c
		s.GracefulStop()
	}()

	api.RegisterPCAPServer(s, &server{})
	if err := s.Serve(listener); err != nil {
		log.Fatalf("Failed to Serve(): %v", err)
	}
}
