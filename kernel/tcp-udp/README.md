# TCP-UDP Content Based Router
 
The UDP-UDP CBR accepts ingress IPv4 TCP packets on port `7777`, reads the first four bytes of data in the payload, and egresses UDP packets on port `7777` to the correct destination server.
 
This is the most recent implementation of the XDP CBR and is partially functional, but is missing some features for viability as discussed in the `Functionality` section.
 
## Implementation
 
### Maps
 
```
struct bpf_map_def SEC("maps") xdp_server_ips =
  {
   .type        = BPF_MAP_TYPE_ARRAY,
   .key_size    = sizeof(__u32),
   .value_size  = sizeof(struct ip),
   .max_entries = SERVERS + 1
  };
 
struct bpf_map_def SEC("maps") tx_port =
  {
   .type = BPF_MAP_TYPE_DEVMAP,
   .key_size = sizeof(int),
   .value_size = sizeof(int),
   .max_entries = 256,
  };
 
struct bpf_map_def SEC("maps") redirect =
  {
   .type = BPF_MAP_TYPE_HASH,
   .key_size = sizeof(char),
   .value_size = sizeof(__u32),
   .max_entries = 256,
  };
```
 
The content based router uses three BPF maps, `xdp_server_ips`, `tx_port`, and `redirect`.
 
`xdp_server_ips` is an array of `struct ip`, as defined in `cbr.h`, which contains the IP addresses of the destination servers. Index 0 contains the IP address of the CBR server and index 1+ contains the destination server IPs.
 
`tx_port` is a device map which contains the redirect interface. The input index is the ingress interface and the output is the interface to redirect to for packet egress. This map is used with the call to `bpf_redirect_map`. 
 
### Debugging
 
```
  char fmt[] = "Received message \"%s\", routing to machine %d\n";
  char fwdError[] = "Forwarding Table Error %x\n";
  char redirectError[] = "Redirect Map Lookup Error\n";
  char ipError[] = "IP Map Lookup Error\n";
  char txError[] = "TX Map Lookup Error\n";
  char adjustError[] = "Adjust Tail Error\n";
```
These strings are used for printing to `trace_pipe` through the `bpf_trace_printk` function. There is an overhead to these printing and they should be removed for a production version of the program.
 
### Protocol Checking
 
```
  void *data = (void *)(long) ctx->data;
  void *data_end = (void *)(long) ctx->data_end;
 
  struct ethhdr *eth = data;
  if (eth + 1 > data_end) return XDP_PASS; 
  if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
 
  struct iphdr * iph = data + sizeof(struct ethhdr);
  if (iph + 1 > data_end) return XDP_PASS;
  if (iph->protocol != IPPROTO_TCP) return XDP_PASS;
 
  struct tcphdr *th = (struct tcphdr *) (iph + 1);
  if (th + 1 > data_end) return XDP_PASS;
  if (MSB(th->dest)) != 7777) return XDP_PASS;
```
 
Since XDP programs are run on all packets, this part of the program determines if the incoming packet is an IPV4 TCP packet on port 7777, if so, the program continues, otherwise, the program will return `XDP_PASS`.
 
### Determine Destination Server
 
```
  char *payload = (char *) iph + (th->doff * 4) + sizeof(struct tcphdr);
  if (payload + 4 > data_end) return XDP_PASS;
  if (payload[0] == 'c' && payload[1] == 'b' && payload[2] == 'r') {
    
    char machine = payload[3];
    char printMachine[] = "0";
    printMachine[0] = machine;
    
    __u32 *machineNumber = bpf_map_lookup_elem(&redirect, &machine);
    if (!machineNumber) {
      bpf_trace_printk(redirectError, sizeof(redirectError));
      return XDP_ABORTED;
    }
    
    __u32 hostMachine = 0;
    bpf_trace_printk(fmt, sizeof(fmt), printMachine, *machineNumber);
```
 
This portion of the code is where the content of the payload is read. Since there is currently no way for the program to determine if the TCP packet is part of the handshake, an acknowledgement, or a data packet, the first four bytes are used. In a data packet the first three bytes will contain `cbr` and the fourth byte will be the destination server. The location of these data bytes is calculated and the `redirect` map is used to determine the destination server number. 
 
### Contruct UDP Header
```
      int diff = (th->doff * 4) - sizeof(struct udphdr);
      //int dsize = MSB(iph->tot_len) - (sizeof(struct iphdr) + (th->doff * 4));
 
      char *dataLocation = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (th->doff * 4);
      char *udpEnd = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
      dsize = dsize & 0xffff;
      if (dataLocation + 5 > data_end) return XDP_PASS;
      __builtin_memcpy(udpEnd, dataLocation, 5);  
      
      struct udphdr *uh = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
      uh->dest = MSB(7777);
      uh->source = MSB(0);
      uh->check = MSB(0);
      uh->len = MSB(dsize + sizeof(struct udphdr));
```
Since the ingress payload protocol was TCP, and the egress payload is UDP, a UDP header needs to be constructed. Currently the program only supports a fixed payload size, so the 5 bytes of TCP data is copied to the end of the UDP header. 
 
The program still computes the data size and the difference in lengths for future use and for the `bpf_xdp_adjust_tail` call.
 
The destination and source ports, checksum, and length fields of the UDP header are also filled in.
 
### Modify IP Header
```
      struct ip *destValue = bpf_map_lookup_elem(&xdp_server_ips, machineNumber);
      struct ip *srcValue = bpf_map_lookup_elem(&xdp_server_ips, &hostMachine);
 
      if (!destValue || !srcValue) {
        bpf_trace_printk(ipError, sizeof(ipError));
        return XDP_ABORTED;
      }
 
      iph->daddr = destValue->addr;
      iph->saddr = srcValue->addr;
      iph->protocol = IPPROTO_UDP;
      iph->tot_len = MSB(MSB(iph->tot_len) - diff);
      iph->check = 0;
```
 
The destination server number is used with the `xdp_server_ips` map to retrieve its IP address. In addition, the IP address of the CBR server is retrieved from the same map.
 
These IPs are then inserted into the IP header's destination address and source address fields, respectively.
 
In addition, the IP payload protocol is changed to UDP and the difference in TCP vs UDP header lengths is subtracted from the total length field.
 
### IP Checksum
```
      iph->check = 0;
    
      uint32_t sum = 0;
      uint8_t * msg = data + sizeof(struct ethhdr);
      
      for (int i = 0; i < 20; i += 2) {
        sum += (((uint16_t) msg[i]) << 8) + msg[i+1];
      }
      
      sum = (sum >> 16) + (sum & 0xFFFF);
      sum = (uint16_t) ~sum;
      sum = ((sum & 0xFF00) >> 8) + ((sum & 0x00FF) << 8);
      
      iph->check = sum;
```
Since the IP header fields were changed, this code recomputes the checksum. Due to limitations of the BPF verifier, the loop is fixed for an IP header length of 20 bytes, therefore the `Options` field of the IP header can not be used.
 
### Forwarding Table
```
      int x = ctx->ingress_ifindex;
      int *ifindex = bpf_map_lookup_elem(&tx_port, &x);
      if (!ifindex) {
        bpf_trace_printk(txError, sizeof(txError));
        return XDP_ABORTED;
      }
    
      struct bpf_fib_lookup fib_params = {};
      fib_params.family = 2;
      fib_params.tos = iph->tos;
      fib_params.l4_protocol=iph->protocol;
      fib_params.sport = 0;
      fib_params.dport = 0;
      fib_params.tot_len = bpf_ntohs(iph->tot_len);
      fib_params.ipv4_src = iph->saddr;
      fib_params.ipv4_dst = iph->daddr;
      fib_params.ifindex = *ifindex;
      
      int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
```
The `tx_port` map is used to determine which interface should be used for egress and then a call to `bpf_fib_lookup` returns the source and destination MAC address for the ethernet header.
 
### Adjust Tail and Redirect
 
```
      if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
 
        if (bpf_xdp_adjust_tail(ctx, -diff) != 0) {
          bpf_trace_printk(adjustError, sizeof(adjustError));
          return XDP_ABORTED;
        }
 
        return bpf_redirect_map(&tx_port, ctx->ingress_ifindex, 0);
 
      }
    
      bpf_trace_printk(fwdError, sizeof(fwdError), rc);
```
If the forwarding table lookup is successful, the source and destination MAC address is copied into the ethernet header. Next, `bpf_xdp_adjust_tail` is used to shrink the packet since the new UDP header is smaller than the old TCP header. Finally, `bpf_redirect_map` is called to redirect the packet.
 
## Functionality
 
This implementation of the CBR is closer to a production version but is not viable due to a lack of XDP features.
 
As implemented, the program will correctly identify a TCP data packet containing `cbr` as the first three bytes, convert the TCP packet to UDP, and forward the packet to the correct destination machine. The program 
will not send a TCP acknowledgement and does not support variable payload sizes. These shortcomings are discussed further below.
 
### TCP Data Packet
 
Currently the program uses the first three bytes of the TCP payload to determine if the TCP packet contains data or if it is a handshake or acknowledgement packet. A better way to identify TCP data packets (either by reading the packet itself or checking with the userspace TCP server if the connection is currently open and awaiting a data packet) is needed.
 
### TCP Server
 
In order for the TCP based CBR to function, a TCP server needs to be running on port 7777 in userspace. Packets which are for setting up the connection are passed through to userspace, but the data packets containing `cbr` are not. Since the userspace server never receives the packets, an acknowledgement is never sent. This causes the client to continuously resend the packet.
 
In order for this to be fixed, [XDP needs to add support for multiple actions per packet](https://www.spinics.net/lists/xdp-newbies/msg01680.html). This will allow the packet to be redirected to the destination server as well as passed to userspace for handling by the TCP server.
 
### Variable Payload Size
 
Due to the BPF compiler and verifier, `__builtin_memcpy` only supports constant sizes. This call to `__buildin_memcpy` is used to copy the TCP payload data from the end of the TCP header to the end of the UDP header.Additional functionality of variable sizes is needed in order to support TCP payloads of variable lengths. Until then, all TCP data packets must be of a fixed size (currently set to 5).