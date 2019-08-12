//go:generate protoc -I ../../api --go_out=plugins=grpc:../../api ../../api/pcapserver.proto

package main

import (
    "context"
    "log"
    "net"

    pb "github.com/mpontillo/pcapserver/api"
    "google.golang.org/grpc"
)

const (
    port = ":50051"
)

type server struct{}

func (s *server) Listen(ctx context.Context, in *pb.ListenRequest) (*pb.ListenReply, error) {
    log.Printf("Received: (%v, %v)", in.Filter, in.Interface)
    return &pb.ListenReply{
        Success: true,
    }, nil
}


func main() {
    lis, err := net.Listen("tcp", port)
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }
    s := grpc.NewServer()
    pb.RegisterPCAPServer(s, &server{})
    if err := s.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}
