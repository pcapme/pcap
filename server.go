package pcap

import (
	"context"
	"github.com/mpontillo/pcap/api"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"os/signal"
)

type server struct{}

func (s *server) Init(ctx context.Context, in *api.InitRequest) (*api.InitReply, error) {
	log.Printf("Init(%+v)", in)
	filter := in.GetFilter()
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
	resultInterfaces := make([]*api.Interface, len(interfaces))
	for i, iface := range interfaces {
		resultInterface := &api.Interface{Name: iface.Name}
		resultAddresses := make([]*api.Address, 0, 8)
		resultAddresses = append(resultAddresses, &api.Address{
			Type: api.AddressType_HARDWARE,
			Value: iface.HardwareAddr.String(),
		})
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip := net.ParseIP(addr.String())
			if ip.To4() != nil {
				// Found an IPv4 address.
				resultAddresses = append(resultAddresses, &api.Address{
					Type: api.AddressType_IPV4,
					Value: iface.HardwareAddr.String(),
				})
			} else {
				// Found an IPv6 address.
				resultAddresses = append(resultAddresses, &api.Address{
					Type: api.AddressType_IPV6,
					Value: iface.HardwareAddr.String(),
				})
			}
		}
		resultInterface.Addresses = resultAddresses
		resultInterfaces[i] = resultInterface
	}
	result.Success = true
	result.Interfaces = resultInterfaces
	return result, nil
}

func StartUnixSocketServer() {
	listener, err := net.Listen("unix", DefaultSocketPath)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
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
		log.Fatalf("failed to serve: %v", err)
	}
}
