# User

This directory contains `loader.c`, for loading the XDP program onto an interface, and `map.c` for populating the BPF maps.

## Loader

Loader uses the `bpf/libbpf.h` library to load an XDP program onto the specified interface. The loader is modified version of `xdp_loader.c` from the [xdp-tutorial repository](https://github.com/xdp-project/xdp-tutorial/blob/master/basic02-prog-by-name/xdp_loader.c). Its implementation is described below.

### Constants
```
char *interfaceName = "wlp2s0";
char *xdpFilename = "xdp_kernel.o";
char *xdpSection = "xdp";
int xdpFlags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
char *map = "/sys/fs/bpf/wlp2s0";
char *mapName = "/sys/fs/bpf/wlp2s0/tx_port";
```

These variables are used in loading the XDP program. They are specific to your development system and need to be changed accordingly. In future versions this could be done through command line arguments.

- `interfaceName` is the interface which the XDP program will be loaded onto.
- `xdpFilename` is the name of the compiled XDP program which will be loaded.
- `xdpSection` is the section of the XDP program which will be loaded
- `map` is the file directory which maps will be pinned to
- `mapName` is one of the maps of the XDP program and is used to determine if a mapped has already been pinned and needs to be deleted before loading the program.

### Convert Interface to ID
```
  /* Determine interface ID from its name*/
  printf("Converting interface name to index\n");
  
  int interfaceIndex = if_nametoindex(interfaceName);
  if (interfaceIndex == 0) perror("Interface Index");
  printf("Converted interface name %s to interface index %i\n", interfaceName, interfaceIndex);
```

The libbpf functions take interface IDs and not names, so `interfaceName` is converted to its ID.

### Detach Current XDP Program
```
 /* Attempt to detatch a current program on that interface */
  printf("Attempting to detach the current program\n");

  __u32 currentProgramID;
  error = bpf_get_link_xdp_id(interfaceIndex, &currentProgramID, xdpFlags);
  if (error) {
    printf("Error getting link XDP ID\n");
    exit(1);
  }

  if (!currentProgramID) {
    printf("No current program loaded\n");
  } else {
    error = bpf_set_link_xdp_fd(interfaceIndex, -1, xdpFlags);
    if (error < 0) {
      printf("Error detaching current program %i\n", currentProgramID);
      exit(1);
    }
    printf("Current program detached\n");
  }
```
If an XDP program is already attached to the interface, this code attempts to detach it.

### Load BPF Program
```
  /* Load the BPF program */
  printf("Loading BPF program from %s\n", xdpFilename);
  
   struct bpf_prog_load_attr programAttributes =
     {
      .prog_type = BPF_PROG_TYPE_XDP,
      .ifindex = 0,
      .file = xdpFilename,
     };

   int programFD = -1;
   error = bpf_prog_load_xattr(&programAttributes, &bpfObject, &programFD);

   if (error) {
     printf("Error loading BPF program\n");
     exit(1);
   }

   printf("Loaded BPF program\n");
```
This code loads the BPF program from the `xdpFilename` into the kernel.

### Find BPF Section
```
   /* Find BPF Section */
   printf("Finding BPF section %s\n", xdpSection);

   struct bpf_program *bpfProgram = bpf_object__find_program_by_title(bpfObject, xdpSection);
   if (!bpfProgram) {
     printf("Error finding BPF section\n");
     exit(1);
   }

   programFD = bpf_program__fd(bpfProgram);
   if (programFD <= 0) {
     printf("Error finding BPF FD\n");
     exit(1);
   }

   printf("Found BPF section\n");
```
This code finds the BPF section as specified in `xdpSection`.

### Attach XDP Program
```
   /* Attach XDP Program */
   printf("Attaching XDP program\n");

   error = bpf_set_link_xdp_fd(interfaceIndex, programFD, xdpFlags);

   if (error < 0) {
     printf("Error attaching XDP program\n");
     exit(1);
   }

   printf("XDP program attached\n");
```
This code attaches the XDP program to the interface.

### Remove Old Maps
```
   /* Remove old maps */
   printf("Removing old maps\n");

   if (access(mapName, F_OK) != -1) {
     error = bpf_object__unpin_maps(bpfObject, map);
     if (error) {
       printf("Error removing old maps\n");
       exit(1);
     }
     printf("Old maps removed\n");
   } else {
     printf("No maps found\n");
   }
```

If the file located at `mapName` exists, it means that the maps have already been created. This code unpins those maps. If you do not want to recreate maps every time the program is loaded, the program can terminate after it has determined that the maps already exist.

### Pin Maps
```
   /* Pin maps */
   printf("Pinning maps\n");

   error = bpf_object__pin_maps(bpfObject, map);
   if (error) {
     printf("Error pinning maps\n");
     exit(1);
   }

   printf("Pinned maps\n");
```
This code pins the maps to the directory specified in `map`.

## Map

Loader uses the `bpf/libbpf.h` library to populate the BPF Maps pinned by the loader. Its implementation is described below.

### Constants
```
char *txMapName = "/sys/fs/bpf/wlp2s0/tx_port";
char *txMapSource = "wlp2s0";
char *txMapRedirect = "gw0";

char *ipsMapName = "/sys/fs/bpf/wlp2s0/xdp_server_ips";
char *ips[] = {"10.0.0.1", "10.0.0.2", "10.0.0.3"};

char *contentMapName = "/sys/fs/bpf/wlp2s0/redirect";
char machines[] = {'b', 'c'};
```

These variables are used in populating the BPF maps. They are specific to your development system and need to be changed accordingly. In future versions this could be done through command line arguments.

- `txMapName` is the directory and map name for the `tx_port` map
- `txMapSource` is the ingress interface for the CBR
- `txMapRedirect` is the egress interface for the CBR
- `ipsMapName` is the directory and map name for the `xdp_server_ips` map
- `ips` is an array of IP addresses for the destination servers with index 0 being the IP address of the CBR server
- `contentMapName` is the directory and map name for the `redirect` map
- `machines` is an array for the payload byte used for identifying the destination server. Index `n` corresponds to server `n + 1`

## TX Port

```
  int txPortFD = bpf_obj_get(txMapName);
  if (txPortFD < 0) {
    printf("Error finding %s map\n", txMapName);
    exit(1);
  }

  int sourceIndex = if_nametoindex(txMapSource);
  if (sourceIndex == 0) perror("Source Index");
  
  int redirectIndex = if_nametoindex(txMapRedirect);
  if (redirectIndex == 0) perror("Redirect Index");
  
  error = bpf_map_update_elem(txPortFD, &sourceIndex, &redirectIndex, 0);
  if (error) {
    printf("Error updating tx port\n");
    exit(1);
  }

  printf("tx_port: redirecting %s:%i to %s:%i\n", txMapSource, sourceIndex, txMapRedirect, redirectIndex);
```

This code converts the `txMapSource` and `txMapRedirect` to interface IDs and adds the redirect mapping to the `tx_port` map.

## IPs
```
 int ipsFD = bpf_obj_get(ipsMapName);
  if (ipsFD < 0) {
    printf("Error finding %s map\n", ipsMapName);
  }

  for (__u32 key = 0; key < SERVERS + 1; key++) {
    struct ip data = { .addr = inet_addr(ips[key]) };
    error = bpf_map_update_elem(ipsFD, &key, &data, 0);
    if (error) {
      printf("Error updating ips\n");
      exit(1);
    }
    printf("ips: set ip %i to %s\n", key, ips[key]);
  }
```

This code adds the IPs from `ips` into a struct and stores them in the `xdp_server_ips` map.

## Content
```
int contentFD = bpf_obj_get(contentMapName);
  if (contentFD < 0) {
    printf("Error finding %s map\n", contentMapName);
  }

  for (__u32 key = 1; key <= SERVERS; key++) {
    error = bpf_map_update_elem(contentFD, &machines[key - 1], &key, 0);
    if (error) {
      printf("Error updating content\n");
      exit(1);
    }
    printf("content: routing %c to machine %i\n", machines[key - 1], key);
  }
```
This code adds the content values from `machines` to the `redirect` map.