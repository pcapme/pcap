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

func (s *server) GetInterfaces(ctx context.Context, in *api.GetInterfacesRequest) (*api.GetInterfacesReply, error) {
	log.Printf("Received: %v", in)
	return &api.GetInterfacesReply{
		Success: true,
	}, nil
}

func (s *server) Init(ctx context.Context, in *api.InitRequest) (*api.InitReply, error) {
	log.Printf("Received: %v", in)
	filter := in.GetFilter()
	err := Capture(CaptureRequest{Filter: filter, Interfaces: in.GetInterfaces()})
	return &api.InitReply{
		Success: err == nil,
	}, nil
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
