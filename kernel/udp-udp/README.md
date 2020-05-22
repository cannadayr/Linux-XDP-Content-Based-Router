# UDP-UDP Content Based Router

The UDP-UDP CBR accepts ingress UDP packets on port `7777`, reads the first byte of data in the payload, and egresses UDP packets on port `7777` to the correct destination server.

## Implementation

