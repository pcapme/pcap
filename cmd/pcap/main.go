package main

import (
	"context"
	"github.com/mpontillo/pcap"
	"log"
	"os"
	"time"

	pb "github.com/mpontillo/pcap/api"
	"google.golang.org/grpc"
)

const defaultInterface = "eth0"

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial("unix://"+pcap.DefaultSocketPath, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewPCAPClient(conn)

	// Contact the server and print out its response.
	iface := defaultInterface
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ifaces := []string{iface}
	initRequest := &pb.InitRequest{}
	initRequest.OptionalFilter = &pb.InitRequest_Filter{Filter: "arp"}
	initRequest.Interfaces = ifaces
	r, err := c.Init(ctx, initRequest)
	if err != nil {
		log.Fatalf("Could not listen: %v", err)
	}
	log.Printf("Result: success=%t (%T): %+v", r.Success, r, r)
}
