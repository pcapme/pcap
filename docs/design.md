# pcap/pcapd - design document

### Introduction

Normally, when you want to capture packets for monitoring or diagnostic purposes, you have a few basic choices:

* Use something like `libpcap` or `AF_PACKET` directly. This often requires your process to be granted additional privileges, such as running as `root`, or having `CAP_NET_RAW` (which can be problematic to grant to the class of "things that are not binaries", such as Python scripts).

* Use something like `tcpdump` or `wireshark` to look at traffic in real-time. This often requires `sudo` or `root` privileges, and/or configuring your system to allow packet capture depending on membership in a group. This situation is inconsistent and not ideal.

The `pcap` project aims to create a gRPC based packet capture interface which can be used from the local machine via a UNIX socket. (With proper authentication, it could also be used remotely.)

## Example Usage

The `pcapd` daemon will be able to be interrogated via the `pcap` command line tool. Below are some example use cases that are envisioned.

### Initializing a Capture

To initialize a capture

```
pcap init [<remote>:][interface] [filter] [--alias <name>]
```

Using an empty interface name will attempt to listen on every available interface.

If `pcap init` specifies a combination of an interface and filter that is already in-use, a new alias to the existing entry will be created.

### Starting a Capture

```
pcap start [remote:][<id|alias>] [--all]
```

### Stopping a Capture

```
pcap stop [remote:]<id|alias|--all>
```

### Getting Saved Capture Data

```
pcap replay [remote:]<id|alias> [--live]
```

Outputs all saved capture data in the form of a `pcap-savefile`.

Optionally continues the output stream,

### Getting Capture Data in Real Time

```
pcap listen [remote:]<id|alias>
```

Listens to the live packet capture stream for the specified remote.

### Adding a Remote

```
pcap remote add <name> <url>
```

## Communication Methods

For local connections, a UNIX socket will be used.

For remote connections, `pcapd` will listen on port `2020` for its communication. This will be replaced by an IANA-registered port number in the future. An authenticated TLS connection will be used for any remote connections. Allowing remote connections will not be the default.

## Challenges

Capturing packets from a remote source will require adjusting the filter to exclude the transport-layer stream being used to transfer the capture data. This can most likely be narrowed down to a particular TCP (source, destination) port, assuming the socket can be queried to find out that information.


