//go:generate protoc -I ../../api --go_out=plugins=grpc:../../api ../../api/pcapd.proto

package main

import "github.com/mpontillo/pcap"

func main() {
	pcap.StartUnixSocketServer()
}
