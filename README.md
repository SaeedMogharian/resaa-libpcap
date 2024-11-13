# LibPcap
Home page: [https://www.tcpdump.org/](https://www.tcpdump.org/)


## Repo
[https://github.com/the-tcpdump-group/libpcap](https://github.com/the-tcpdump-group/libpcap)

## The Sniffer's Guide to Raw Traffic
[http://yuba.stanford.edu/~casado/pcap/section1.html](http://yuba.stanford.edu/~casado/pcap/section1.html)
- **Packet Capture** Roughly means, _to grab a copy of packets off of the wire before they are processed by the operating system_. packet capture is widely used in network security tools to analyze raw traffic for detecting malicious behaviour (scans and attacks), sniffing, fingerprinting and many other (often devious) uses.
- **libpcap** "provides implementation-independent access to the underlying packet capture facility provided by the operating system" (Stevens, UNP page. 707). So pretty much, libpcap is the library we are going to use to grab packets right as they come off of the network card.

-- The codes did not run and used deprecated methods


## Programming with Libpcap   - Sniffing the network
[http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf)


## Develop a Packet Sniffer with Libpcap
[https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/](https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/)
Libpcap is an open source C library that provides an API for capturing packets directly from the datalink layer of Unix derived operating systems. It is used by popular packet capture applications such as [tcpdump](https://www.tcpdump.org) and [snort](https://www.snort.org) that enables them to run on just about any flavor of Unix.

`pcap.h` header file to gain access to library functions and constants  


--> The goal of the example packet sniffer application is to collect raw IP packets traversing a network and inspect their header and payload fields to determine protocol type, source address, destination address and so on.


code: https://github.com/vichargrave/sniffer

--> The code run good!!

--> Change the `handle_pcap` function to reach the desired function

## Using libpcap in C
[https://www.devdungeon.com/content/using-libpcap-c](https://www.devdungeon.com/content/using-libpcap-c)
Depricated!!


## BPF and tcpdump
[https://andreaskaris.github.io/blog/networking/bpf-and-tcpdump/](https://andreaskaris.github.io/blog/networking/bpf-and-tcpdump/)

## Wireshark Wiki
https://wiki.wireshark.org/libpcap
Wireshark/TShark uses libpcap to capture live network data.

Installed usually by default on UNIX: `dpkg -s libpcap-dev`

Two Windows versions of libpcap are available. The older one is named [WinPcap](https://wiki.wireshark.org/WinPcap); it is no longer actively being maintained, and is based on an older version of libpcap. The newer one is called [Npcap](https://nmap.org/npcap/)

https://wiki.wireshark.org/Development/LibpcapFileFormat

# 2. Code
Here's a high-level object structure diagram for the provided C++ code. This diagram captures the main objects and their relationships, giving a visual overview of how the code components interact with each other:

### Diagram Key
- **Classes** are represented as rectangles.
- **Arrows** indicate relationships (e.g., "uses", "contains").
- **Methods** and **attributes** are mentioned inside the class boxes where relevant.

---

```plaintext
+--------------------+
|      Application   |
+--------------------+
| - interface_prim   |
| - interface_secn   |
| - filter           |
| - count            |
| - stats_manager    |
| - primary_session  |
| - secondary_session|
+--------------------+
| + run(argc, argv)  |
| + stop()           |
| + parseArguments() |
+--------------------+
         |
         v
+----------------------+
|   CaptureSession     |
+----------------------+
| - interface_name     |
| - sniff_handle       |
| - packet_handler     |
| - stop_flag          |
+----------------------+
| + startCapture()     |
| + stopCapture()      |
| + getStats()         |
| + getPacketHandler() |
+----------------------+
         |
         v
+--------------------+
|   PacketHandler    |
+--------------------+
| - injection_handle |
| - interface_name   |
| - stats_manager    |
| - injection_failures|
| - packets_processed |
+--------------------+
| + handle()         |
| + packetCallback() |
| + print()          |
+--------------------+
         |
         v
+--------------------+
|  StatisticsManager |
+--------------------+
| - ip_statistics    |
+--------------------+
| + update()         |
| + print()          |
+--------------------+
         ^
         |
+--------------------+
|      IpStats       |
+--------------------+
| - packets_sent     |
| - bytes_sent       |
| - interface        |
+--------------------+
| + (constructor)    |
+--------------------+

Other Supporting Components:
----------------------------
+--------------------+
| Unique Pcap Handle |
+--------------------+
| Wrapper for pcap_t |
+--------------------+

+--------------------+
| Signal Handling    |
+--------------------+
| Handles SIGINT,    |
| SIGTERM, SIGQUIT   |
+--------------------+

+--------------------+
| PCAP Library       |
+--------------------+
| Used for packet    |
| capture, filtering,|
| injection, etc.    |
+--------------------+
```

---

### Explanation of Relationships:
1. **Application**:
   - Manages the overall program.
   - Uses **CaptureSession** objects for primary and secondary interfaces.
   - Has a **StatisticsManager** to collect and display IP statistics.

2. **CaptureSession**:
   - Encapsulates a network interface and a packet capture handle (`sniff_handle`).
   - Utilizes a **PacketHandler** to manage captured packets.
   - Uses static utility methods for creating PCAP handles.

3. **PacketHandler**:
   - Processes packets and updates the **StatisticsManager** with packet data.
   - Handles packet injection and keeps track of injection success/failure.

4. **StatisticsManager**:
   - Maintains a map of **IpStats**, which hold per-IP statistics (packets sent, bytes sent, etc.).
   - Provides functionality to update and print IP-level statistics.

5. **IpStats**:
   - Represents statistics for a specific IP address.
   - Contains attributes like `packets_sent`, `bytes_sent`, and the interface name.

6. **PCAP Library**:
   - Interfaced through methods like `pcap_open_live`, `pcap_inject`, `pcap_loop`, and others.
   - Used extensively in **CaptureSession** and **PacketHandler**.

7. **Signal Handling**:
   - Ensures graceful termination of the application when signals like SIGINT are received.
   - Links directly to the global **Application** instance.

This diagram and explanation capture the primary relationships and workflows in your code. Let me know if you'd like a visual rendering of this structure!


