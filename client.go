package pcap

import (
	"context"
	"fmt"
	"github.com/mpontillo/pcap/api"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"log"
	"os"
	"time"
)

const defaultInterface = "eth0"

type Client struct {
	socket *grpc.ClientConn
	api    api.PCAPClient
}

func NewUNIXSocketClient() *Client {
	connection := new(Client)
	socket, err := grpc.Dial("unix://"+DefaultSocketPath, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	connection.socket = socket
	connection.api = api.NewPCAPClient(connection.socket)
	return connection
}

func (c *Client) Disconnect() {
	c.socket.Close()
}

func (c *Client) Init() {
	// Contact the server and print out its response.
	iface := defaultInterface
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ifaces := []string{iface}
	initRequest := &api.InitRequest{}
	initRequest.OptionalFilter = &api.InitRequest_Filter{Filter: "arp"}
	initRequest.Interfaces = ifaces
	r, err := c.api.Init(ctx, initRequest)
	if err != nil {
		log.Fatalf("Could not initialize: %v", err)
	}
	log.Printf("Result: success=%t (%T): %+v", r.Success, r, r)
}

func Execute() {
	var rootCmd = &cobra.Command{
		Use:   "pcap",
		Short: "pcap: a command-line tool for managing packet captures.",
		Long: `pcap: a command-line tool for managing packet captures.
        Uses gRPC over a UNIX socket to communicate with a 'pcapd' server.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Do Stuff Here
			fmt.Printf("cmd: %+v\nargs:%+v\n\n", cmd, args)
			client := NewUNIXSocketClient()
			client.Init()
			client.Disconnect()
		},
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
