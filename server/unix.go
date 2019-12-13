package server

import (
	"context"
	"github.com/pcapme/pcap/api"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

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
	// User/group permission, but not just anyone.
	if err := os.Chmod(DefaultSocketPath, 0770); err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	context.WithCancel(context.Background())
	go func() {
		<-c
		log.Println("Interrupt received; stopping gracefully...")
		// Before we stop the service, we need to notify any streams that we're shutting down.
		close(ShuttingDown)
		s.GracefulStop()
	}()

	api.RegisterPCAPServer(s, &Server{})
	if err := s.Serve(listener); err != nil {
		log.Fatalf("Failed to Serve(): %v", err)
	}
}
