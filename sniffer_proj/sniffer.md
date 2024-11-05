# sniffer

https://github.com/vichargrave/sniffer

Example code from my Develop a Packet Sniffer with libpcap blog.

## Build

1. cd to the 'sniffer' directory.
2. Type 'make'.

## Run

Run by specifying an interface and a Berkeley packet filter expression. For 
example this statement will capture all the inbound and outbound TCP packets 
port 80 packets on interface eth0:

```
./sniffer -i eth0 tcp port 80
```

# How it works (ai generated)
The code you provided is a packet sniffer program written in C that uses the `libpcap` library. Here's a breakdown of what it does:

### Overview:
- The program captures packets from a network interface using `libpcap`.
- It gathers statistics about IP traffic, such as the number of packets sent and received, and the number of bytes transmitted between IP addresses.
- The program can run with command-line arguments specifying which network interface to use and optionally a filter for capturing specific types of traffic.

### Key Components:
1. **Libraries Included**:
   - The program includes standard C libraries like `stdio.h`, `stdlib.h`, and network-related headers like `pcap.h` and `netinet/ip.h`.
   
2. **Data Structures**:
   - `struct IpStats`: This is a linked list structure used to store IP statistics for each IP address. Each entry contains information such as:
     - IP address (`ip`)
     - Number of packets received and sent (`packets_received`, `packets_sent`)
     - Number of bytes received and sent (`bytes_received`, `bytes_sent`)

3. **Functions**:
   - `find_or_add_ip(const char* ip)`: Searches the linked list for an IP address. If found, it returns the corresponding node; if not, it adds a new node to the linked list.
   - `create_pcap_handle(char* device, char* filter)`: Sets up the packet capture handle. This function:
     - Finds the appropriate device if none is specified.
     - Opens the device for capturing packets.
     - Compiles and sets a filter for packet capture.
   - `get_link_header_len(pcap_t* handle)`: Determines the link layer type and sets the appropriate link header length based on the network type.
   - `packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr)`: The main packet handler. This function:
     - Extracts the IP header and retrieves source and destination IP addresses.
     - Updates packet statistics for both the source and destination IPs in the linked list.
   - `print_ip_statistics()`: Prints out the gathered statistics for each IP address.
   - `free_ip_statistics()`: Frees the memory used by the linked list storing IP statistics.
   - `stop_capture(int signo)`: Stops the packet capture, prints final statistics, and frees resources.

4. **Signal Handling**:
   - `signal(SIGINT, stop_capture)`: Registers a signal handler for stopping packet capture cleanly on receiving termination signals (e.g., `Ctrl+C`).

5. **Main Flow (`main`)**:
   - Processes command-line arguments to set the network interface and filter.
   - Creates the packet capture handle using `create_pcap_handle()`.
   - Determines the link layer header length using `get_link_header_len()`.
   - Starts packet capture using `pcap_loop()` which calls `packet_handler()` for each captured packet.
   - When the program stops (due to a signal or completion), it calls `stop_capture()` to display statistics and free resources.

### How It Works:
- **Initialization**: The user can specify which network interface to use and an optional filter using command-line arguments. If none is specified, the program will select the first available interface.
  
- **Packet Capture**:
  - The program creates a packet capture handle for the specified interface.
  - The `packet_handler()` function is called for each captured packet. It extracts the IP header and updates the linked list that stores statistics for each IP address encountered.

- **Statistics**:
  - The program keeps track of how many packets and bytes are received/sent by each IP address.
  - When terminated, it prints the IP statistics gathered.

### Notes:
- The program uses the linked list `ip_statistics` to dynamically track statistics for all IP addresses seen during packet capture.
- `pcap_loop()` is used to capture packets indefinitely or up to a specified count, calling `packet_handler()` for each packet.
- Proper cleanup is performed using `free_ip_statistics()` to free memory used by the linked list.

This code is useful for learning how to use `libpcap` to capture network traffic and gather statistics. It's also a simple demonstration of using linked lists in C to keep track of dynamically changing data like IP addresses seen on a network.