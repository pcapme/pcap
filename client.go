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

func (c *Client) Init(args []string) {
	// Contact the server and print out its response.
	iface := defaultInterface
	if len(args) > 0 {
		iface = args[0]
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
			_ = cmd.Help()
			// fmt.Printf("\n\ncmd: %+v\nargs:%+v\n\n", cmd, args)
		},
	}
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version string.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("pcap version v0.0.1")
		},
	}
	var initCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize a new capture definition.",
		Run: func(cmd *cobra.Command, args []string) {
			client := NewUNIXSocketClient()
			defer client.Disconnect()
			client.Init(args)
		},
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
