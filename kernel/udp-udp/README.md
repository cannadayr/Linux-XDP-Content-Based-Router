# UDP-UDP Content Based Router

The UDP-UDP CBR accepts ingress UDP packets on port `7777`, reads the first byte of data in the payload, and egresses UDP packets on port `7777` to the correct destination server.

## Implementation

This section walks through the code and provides an overview of its functionality. Long sections of code are abbreviated by `...`.

### Maps

```
struct bpf_map_def SEC("maps") xdp_server_ips = {
    ...
};

struct bpf_map_def SEC("maps") tx_port = {
	...
};

struct bpf_map_def SEC("maps") redirect = {
	...
};
```

The content based router uses three BPF maps, `xdp_server_ips`, `tx_port`, and `redirect`.

`xdp_server_ips` is an array of `struct ip`, as defined in `cbr.h`, which contains the IP addresses of the destination servers. Index 0 contains the IP address of the CBR server and index 1+ contain the destination server IPs.

`tx_port` is a device map which contains the redirect interface. The input index is the ingress interface and the output is the interface to redirect to for packet egress. This map is used with the call to `bpf_redirect_map`. 

### Debugging

``` 
  char fmt[] = "Received message \"%s\", routing to machine %d\n";
  char fwdError[] = "Forwarding Table Error %x\n";
  char redirectError[] = "Redirect Map Lookup Error\n";
  char ipError[] = "IP Map Lookup Error\n";
  char txError[] = "TX Map Lookup Error\n";
```

These strings are used for printing to `trace_pipe` through the `bpf_trace_printk` function. There is an overhead to these printing and they should be removed for a production version of the program.

### Protocol Checking

```
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if (eth + 1 > data_end) return XDP_PASS;
  if (eth->h_proto == __constant_htons(ETH_P_IP)) {
  
    struct iphdr * iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end) return XDP_PASS;
    if (iph->protocol == IPPROTO_UDP) {

      struct udphdr *uh = (struct udphdr *) (iph + 1);
      if (uh + 1 > data_end) return XDP_PASS;
      if (MSB(uh->dest) == 7777) {
```

Since XDP programs are run on all packets, this part of the program determines if the incoming packet is an IPV4 UDP packet on port 7777, if so, the program continues, otherwise, the program will return `XDP_PASS`.

### Determine Destination Server

```
        uint32_t dataLocation = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
        if (data + dataLocation + 1 > data_end) return XDP_PASS; 

		char * udpDataStart = data + dataLocation;
		char machine = udpDataStart[0];
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

This portion of the code is where the content of the payload is read. The location of the first byte of data is calculated and the `redirect` map is used to determine the destination server number. 

### Change IPs

```
        struct ip *destValue = bpf_map_lookup_elem(&xdp_server_ips, machineNumber);
		struct ip *srcValue = bpf_map_lookup_elem(&xdp_server_ips, &hostMachine);
		
		if (!destValue || !srcValue) {
			bpf_trace_printk(ipError, sizeof(ipError));
			return XDP_ABORTED;
		}
			
		iph->daddr = destValue->addr; 
		iph->saddr = srcValue->addr;
```

The destination server number is used with the `xdp_server_ips` map to retrieve its IP address. In addition, the IP address of the CBR server is retrieved from the same map.

These IPs are then inserted into the IP header's destination address and source address fields, respectively.

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

### Redirect

```
        if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
			__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
			__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
			return bpf_redirect_map(&tx_port, ctx->ingress_ifindex, 0);
		}

		bpf_trace_printk(fwdError, sizeof(fwdError), rc);
```
If the forwarding table lookup is successful, the source and destination MAC address is copied into the ethernet header and `bpf_redirect_map` is called.

## Functionality

This implementation of the CBR functions as expected, but is not viable for production applications due to using UDP for ingress packets. It was originally used as a proof-of-concept and development ground for the basic CBR implementation before development on the TCP-UDP version began.

As implemented, this CBR is limited to 256 destination servers due to a single byte being used for determining the destination server from the payload. In addition, this implementation only supports IPv4 and not IPv6.