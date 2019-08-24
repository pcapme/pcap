//go:generate protoc -I ../../api --go_out=plugins=grpc:../../api ../../api/pcapd.proto

package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/mpontillo/pcap"
	pb "github.com/mpontillo/pcap/api"
	"google.golang.org/grpc"
)

type server struct{}

func (s *server) Listen(ctx context.Context, in *pb.InitRequest) (*pb.InitReply, error) {
	log.Printf("Received: %v", in)
	return &pb.InitReply{
		Success: true,
	}, nil
}

func main() {
	lis, err := net.Listen("unix", pcap.DefaultSocketPath)
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

	pb.RegisterPCAPServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
