# `pcap`

The `pcap` suite is intended to provide an interface to `libpcap` (or other
packet capturing technologies) with an easy-to-use command-line interface.

## Hacking

In order to build the `pcap` suite, you will need to install:

* The `protobuf` tools, including the plugin to generate `.go` files.
  (See the [instructions here](https://github.com/golang/protobuf) for more
  information.)
* A few additional `go`-based dependencies, which can be installed as follows:
  * `go get -u github.com/google/gopacket/pcapgo`
  * `go get -u github.com/olekukonko/tablewriter`
  * `go get -u github.com/spf13/cobra`
  * `go get -u google.golang.org/grpc`
  * `go get -u golang.org/x/sys/unix`

