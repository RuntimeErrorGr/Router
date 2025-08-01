## Router Implementation (Routing, ARP, and ICMP)

### Routing Table Parsing

I implemented routing table parsing from a text file using a `typedef struct my_rtable_entry`.

1. First, I counted how many entries the file contained using a custom function `int count_entries()` defined in `skel.c`, in order to allocate the correct array size.
2. Then, I allocated an array of size `number_of_entries * rtable_size`.
3. The file was then read a second time line by line until EOF.
4. Each line was split into four substrings using `strtok`:
   - prefix IP
   - next hop IP
   - subnet mask
   - interface
5. The resulting values were stored in the routing table using `void myRead_rtable()`.

---

### ARP Protocol Implementation

To handle ARP packets, I considered the following cases:

#### Receiving ARP Packets (`EtherType 0x0806`)

1. **ARP Reply**
   - On receiving an ARP reply, the ARP table is updated with the source MAC address from the packet.
   - All packets in the waiting queue (pending MAC resolution) are processed.
   - This type of packet is typically received after an ARP request has been sent.

2. **ARP Request**
   - If the ARP request is destined for the router, an ARP reply is sent with the MAC address of the router's receiving interface.

#### Sending ARP Requests

- If the router does not know the MAC address of the next hop (i.e., `getARPentry()` returns NULL):
  1. A copy of the original packet is stored in a waiting queue.
  2. An Ethernet header with destination MAC address `ff:ff:ff:ff:ff:ff` (broadcast) is created.
  3. An ARP request is sent to the next hop IP address from the routing table.

---

### Packet Forwarding Logic

To implement packet forwarding:

1. Upon receiving a packet:
   - Check if it's an IP packet.
   - If it's ICMP, extract the required headers.

2. Handle exceptions:
   - If `TTL <= 1`, send an ICMP Time Exceeded message.
   - If the checksum is invalid, drop the packet.

3. Otherwise:
   - Decrement TTL.
   - Update the checksum.
   - Perform a Longest Prefix Match (LPM) in the routing table.
     - *Note: the LPM search is implemented in O(n) time.*

4. If a match is found:
   - If the next hop's MAC address is known, forward the packet using correct MAC addresses.
   - If the MAC address is not known, send an ARP request.

5. If no match is found:
   - Send an ICMP Destination Unreachable message.

---

### ICMP Protocol Implementation

The ICMP protocol handles the following cases:

1. **Echo Request**
   - If the packet is destined for the router, send an Echo Reply.
   - Otherwise, discard the packet.

2. **TTL Expired**
   - If a packet arrives with `TTL <= 1`, send an ICMP Time Exceeded message and drop the packet.

3. **Destination Unreachable**
   - If the router has no route to the destination IP, return an ICMP Destination Unreachable message.

---

### Documentation and Code Reuse

- Main reference: Lab 4.
- Reused code from previous implementations:
  - TTL checking
  - Checksum validation
  - Checksum updating
  - Routing table search
