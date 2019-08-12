package main

import (
	"context"
	"log"
	"os"
	"time"

	pb "github.com/mpontillo/pcapserver/api"
	"google.golang.org/grpc"
)

const (
	address     = "localhost:50051"
	defaultInterface = "eth0"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
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
	r, err := c.Listen(ctx, &pb.ListenRequest{Filter: "arp", Interface: iface})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %b", r.Success)
}

