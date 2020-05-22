# User

This directory contains `loader.c`, for loading the XDP program onto an interface, and `map.c` for populating the BPF maps.

## Loader

Loader uses the `bpf/libbpf.h` library to load an XDP program onto the specified interface. The loader is modified version of `xdp_loader.c` from the [xdp-tutorial repository](https://github.com/xdp-project/xdp-tutorial/blob/master/basic02-prog-by-name/xdp_loader.c). It's implementation is described below.

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