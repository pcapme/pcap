# `pcap`

The `pcap` suite is intended to provide an interface to `libpcap` (or other
packet capturing technologies) with an easy-to-use command-line interface.

## Hacking

### Development Environment Setup

The currently supported development environment for is Ubuntu 18.04 ("bionic").
To bootstrap a development environment, you can do the following:

```
sudo snap install go
sudo apt-get install git build-essential protobuf-compiler-grpc libpcap-dev
```

### Go language setup

In order to build the `pcap` suite, you will first need to install the
`protobuf` tools, including the plugin to generate `.go` files.  See the
[instructions here](https://github.com/golang/protobuf) for more information.

The `go`-based dependencies can be installed as follows:

```
go get -u google.golang.org/grpc
go get -u github.com/golang/protobuf/protoc-gen-go
go get -u golang.org/x/sys/unix
go get -u github.com/google/gopacket/pcapgo
go get -u github.com/olekukonko/tablewriter
go get -u github.com/spf13/cobra
```

You should also make sure that `$GOPATH/bin` is in your path, such as by
ensuring the following environment variables are set:

```
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"
```

### Running the `pcap` suite

The `Makefile` provides a convenient target which will compile `pcapd`, set
the capability bits to allow packet capture, and run the daemon. To start
the daemon, you can simply type:

```
make run
```

When you use `make run`, a `make install` will be run, which will cause the
`pcap` binary to be placed on your `$GOPATH/bin` by `go install`. Therefore,
if `$GOPATH/bin` is on your `$PATH`, you can then test the `pcapd` daemon
interactively by running `pcap`. For example:

```
$ pcap interface list
+-------+--------------------+----------------+---------------------------+
| NAME  | HARDWARE ADDRESSES | IPV4 ADDRESSES |      IPV6 ADDRESSES       |
+-------+--------------------+----------------+---------------------------+
| lo    |                    | 127.0.0.1      | ::1                       |
+-------+--------------------+----------------+---------------------------+
| ens33 | 00:0c:29:79:3d:0d  | 172.16.17.138  | fe80::bafb:4879:cb8e:a017 |
+-------+--------------------+----------------+---------------------------+
```
