# pcap.me design

### Introduction

Normally, when you want to capture packets for monitoring or diagnostic
purposes, you have a few basic choices:

* Use something like `libpcap` or `AF_PACKET` directly. This often requires
  your process to be granted additional privileges, such as running as
  `root`, or having `CAP_NET_RAW`. (This can be problematic to grant to the
  class of "things that are not binaries", such as Python scripts.)

* Use something like `tcpdump` or `wireshark` to look at traffic in real-time.
  This often requires `sudo` or `root` privileges, and/or configuring your
  system to allow packet capture depending on membership in a group. This
  can be is inconsistent and not ideal, since the burden is on the user to
  manage each process conducting  packet capture.

The `pcap` project aims to create a gRPC based packet capture interface which
can be used from the local machine via a UNIX socket. (With proper
authentication, it could also be used remotely.)

## Capture States

The `pcapd` process will keep track of a set of captures, each of which can
be in one of the following states:

* `Pending` - Defines the state of each capture when the server is starting,
  and the state of a capture when it is first added to the system.
* `Active` - Defines the state of a capture currently in-progress.
* `Retrying` - Defines the state of a capture which was previously `Active`,
  but encountered an error (such as the interface now being missing or down).
* `Paused` - Defines the state of a capture that was previously `Active` but
  was paused due to user intervention.
* `Finished` - Defines the state of a capture that was once `Active`, but
  has completed its defined runtime.


## Example Usage

The `pcapd` daemon will be able to be interrogated via the `pcap` command line
tool. Below are some example use cases that are envisioned.

### Initializing a Capture

To initialize a capture:

```
pcap add <interface...> [--filter <filter>] [--name <name>]
         [--snaplen <snaplen>] [--timeout <seconds>]
```

Using a `*` could attempt to listen on every available interface.

### Pausing a Capture

Pause an active, pending, or retrying capture.

```
pcap pause [<name>|--all]
```

### Resuming a Capture

Resume a previously-finished or paused capture, optionally setting a new
duration.

```
pcap resume <name|--all> [--duration <seconds>]
```

### Getting Saved Capture Data

```
pcap replay <name> [--live]
```

Outputs all saved capture data in the form of a `pcap-savefile`.

Optionally continues the output stream "live".

Capture data can also be found on-disk on the server.


### Getting Capture Data in Real Time

```
pcap live-capture <interface> [--filter <filter>]
                  [--snaplen <snaplen>] [--duration <seconds>]
```

Listens to the live packet capture stream for the specified remote.


## Communication Methods

For local connections, a UNIX socket will be used.

For remote connections, `pcapd` will listen on port `2020` for its
communication. This will be replaced by an IANA-registered port number in the
future. An authenticated TLS connection will be used for any remote
connections. Allowing remote connections will not be the default.


## Challenges

Capturing packets from a remote source will require adjusting the filter to
exclude the transport-layer stream being used to transfer the capture data.
This can most likely be narrowed down to a particular TCP (source, destination)
port, assuming the socket can be queried to find out that information.
