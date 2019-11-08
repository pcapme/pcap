package pcap

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pcapme/pcap/api"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"io"
	"log"
	"os"
	"strings"
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

func (c *Client) LiveCapture(ifname string, filter string, format string) {
	// Contact the server and print out its response.
	stream, err := c.api.LiveCapture(context.Background(), &api.CaptureRequest{
		Interface:     ifname,
		Filter:        filter,
		ImmediateMode: true,
	})
	if err != nil {
		log.Fatalf("%v", err)
	}
	var writer *pcapgo.Writer
	// XXX this should be moved after GetHeader below to get the snaplen.
	switch format {
	case "hex":
	case "pcap":
		writer = pcapgo.NewWriter(os.Stdout)
		err = writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}
	for {
		reply, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("%v", err)
		}
		header := reply.GetHeader()
		if header != nil {
		}
		packet := reply.GetData()
		if packet != nil {
			switch format {
			case "hex":
				fmt.Println(hex.Dump(packet.Data))
			case "pcap":
				t := time.Unix(packet.Seconds, int64(packet.Microseconds*1000))
				ci := gopacket.CaptureInfo{
					Timestamp:      t,
					CaptureLength:  len(packet.Data),
					Length:         int(packet.OriginalLength),
					InterfaceIndex: 1, // XXX
				}
				if writer != nil {
					err := writer.WritePacket(ci, packet.Data)
					if err != nil {
						log.Fatalf("%v", err)
					}
				}
			}
		}
	}
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

func renderAddresses(addresses []*api.Address) string {
	result := make([]string, len(addresses))
	for i, address := range addresses {
		result[i] = address.Value
	}
	return strings.Join(result, "\n")
}

func (c *Client) InterfaceList(all bool) {
	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request := &api.InterfaceListRequest{All: all}
	reply, err := c.api.InterfaceList(ctx, request)
	if err != nil {
		log.Fatalf("Error listing interfaces: %v", err)
	}
	//log.Printf("Result: success=%t (%T): %+v", reply.Success, reply, reply)
	data := make([][]string, 0, len(reply.Interfaces))
	for _, iface := range reply.Interfaces {
		data = append(
			data, []string{
				iface.Name,
				renderAddresses(iface.EthernetAddresses),
				renderAddresses(iface.Ipv4Addresses),
				renderAddresses(iface.Ipv6Addresses),
			})
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "Hardware Addresses", "IPv4 Addresses", "IPv6 Addresses"})
	table.AppendBulk(data)
	table.SetRowLine(true)
	table.Render()
}

func validateOutputFormat(outputFormat string, cmd *cobra.Command) {
	switch outputFormat {
	case "hex":
	case "pcap":
	default:
		cmd.Usage()
		os.Exit(1)
	}
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

	var liveCaptureFormat string
	var liveCaptureCmd = &cobra.Command{
		Use:   "live-capture <interface> [filter] [--format=<hex|pcap>]",
		Short: "Start a live capture.",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			validateOutputFormat(liveCaptureFormat, cmd)
			filter := ""
			if len(args) >= 2 {
				filter = args[1]
			}
			ifname := args[0]
			client := NewUNIXSocketClient()
			defer client.Disconnect()
			client.LiveCapture(ifname, filter, liveCaptureFormat)
		},
	}
	liveCaptureCmd.Flags().StringVarP(
		&liveCaptureFormat, "format", "f", "hex",
		"Output format. Can be 'hex' or 'pcap'.")

	var interfaceCmd = &cobra.Command{
		Use:   "interface",
		Short: "Work with interfaces on the pcap host.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	var interfacesListAll bool
	var interfaceListCmd = &cobra.Command{
		Use:   "list",
		Short: "Lists available interfaces.",
		Run: func(cmd *cobra.Command, args []string) {
			client := NewUNIXSocketClient()
			defer client.Disconnect()
			client.InterfaceList(interfacesListAll)
		},
	}
	interfaceListCmd.Flags().BoolVarP(
		&interfacesListAll,
		"all", "a", false,
		"List all interfaces. (By default, only includes those that are link-up.)")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(interfaceCmd)
	rootCmd.AddCommand(liveCaptureCmd)

	interfaceCmd.AddCommand(interfaceListCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
