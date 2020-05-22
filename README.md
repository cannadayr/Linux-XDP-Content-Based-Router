# Linux XDP Content Based Router

This repository contains a proof-of-concept Content Based Router (CBR) implemented using [eXpress Data Path (XDP)](https://www.iovisor.org/technology/xdp) in the Linux kernel.

This project is part of an Independent Study in Linux Networking at Rose-Hulman Institute of Technology. Its purpose was to develop a practical use case for XDP.

## Theory of Operation

A content based router (CBR) examines the payload of an incoming packet and then routes the packet to its intended destination server. This section will provide a high level overview of how the CBR functions and then detail two particular implementations.

### High Level Overview

The CBR resides on a server with two network interfaces. One interface is accessible to the public and is used for packet ingress and the other interface is on a private subnet on which the destination servers reside.

![Topology](cbr-topology.png)

The first step of the CBR is to determine if the ingress packet is one which is intended to be routed. If the protocols and ports are correct, then the CBR begins the routing process.

The CBR inspects the payload of the intended protocol and uses it to make a decision on the destination server. The CBR then performs lookups for the addresses of the destination server and modifies the protocol headers as needed such as replacing destination and source fields or recomputing checksums. Finally, the packet egresses the CBR through the interface on the private subnet.

### Implementations

This CBR has two different implementations, UDP-UDP and TCP-UDP.

The UDP-UDP implementation uses IPV4 UDP packets for both ingress and egress. The TCP-UDP implementation uses IPV4 TCP packets for ingress and IPV4 UDP packets for egress.

## Artifacts

### Enviornment

The `enviornment` folder contains `ip.sh` which sets up a testing enviornment for the CBR on a single Linux machine. This testing enviornment emulates the topology shown above, but non test enviornment topologies can be created instead for development or deployment using cloud or physical machines. Documentation for setting up the test enviornment is detaliled in the directory's README.

### Kernel

The `kernel` folder contains the XDP program code for the UDP-UDP and TCP-UDP implementations found in their respective `udp-udp` and `tcp-udp` subdirectories. Each of these subdirectories also contains a README documenting their implementations and functionality.

### User

The `user` folder contains the `loader.c` for loading the XDP programs onto network interfaces and `map.c` for populating the BPF maps. Documentation for using and modifying the loader and map program is detailed in the directory's README.

### Common

The `common` folder contains the `cbr.h` header file for the kernel and userspace programs. Documentation detailing this header file is detailed in the directory's README.

## Future Work

The initial work on this project was limited to two 10 week independent studies and provides only a proof of concept for this XDP use case. Additional work is needed to add functionality that is needed for viability and analyze performance improvement.

### Timing

### Additional Protocols