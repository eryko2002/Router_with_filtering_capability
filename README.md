# Router_with_filtering_capability

# Router's capabilities:

## Routing based on IP address:
- Determination of the destination subnet (key in the table), output port, and next node (action parameters).
- Support for TTL handling, including packet dropping if necessary.
- Updating the checksum.
## Filtering (blocking) traffic based on:
- Destination IP address.
- Destination port of the transport layer.
- Transport layer protocol.
## Hosts in different subnets:
- Ability to assign static MAC addresses or implementation of ARP protocol handling.
- Substitution to the correct MAC addresses.
- Lack of support for the ICMP protocol.
## Statistics:
- Tracking received/sent packets, separately for each port.
- Recording forwarded packets, for each port.
- Monitoring rejected packets, aggregated for all ports.


# Download VM with installed P4 tools(login: p4,password: p4):
```
https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md
```
# Download Repository:
```
https://github.com/eryko2002/Router_with_filtering_capability.git
```
# How to run:
```
make clean; make run
```
