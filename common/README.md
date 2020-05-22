# Common

`cbr.h` is used in both the kernel and userspace program for the CBR.

## Servers

```
#define SERVERS 2
```

This defines the number of destination servers which is used for the `xdp_server_ips` map.

## struct ip

```
struct ip {
  __u32 addr;
};
```

This define an IP structure which contains a 32 bit IP address used in the `xdp_server_ips` map. This structure would need to be updated for IPv6 destination server support.