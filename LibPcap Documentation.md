Home page: [https://www.tcpdump.org/](https://www.tcpdump.org/)

# Repo
[https://github.com/the-tcpdump-group/libpcap](https://github.com/the-tcpdump-group/libpcap)

# The Sniffer's Guide to Raw Traffic
[http://yuba.stanford.edu/~casado/pcap/section1.html](http://yuba.stanford.edu/~casado/pcap/section1.html)
- **Packet Capture** Roughly means, _to grab a copy of packets off of the wire before they are processed by the operating system_. packet capture is widely used in network security tools to analyze raw traffic for detecting malicious behaviour (scans and attacks), sniffing, fingerprinting and many other (often devious) uses.
- **libpcap** "provides implementation-independent access to the underlying packet capture facility provided by the operating system" (Stevens, UNP page. 707). So pretty much, libpcap is the library we are going to use to grab packets right as they come off of the network card.

[http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf)

[https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/](https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/)

  

[https://www.devdungeon.com/content/using-libpcap-c](https://www.devdungeon.com/content/using-libpcap-c)


[https://andreaskaris.github.io/blog/networking/bpf-and-tcpdump/](https://andreaskaris.github.io/blog/networking/bpf-and-tcpdump/)

# Wireshark Wiki
https://wiki.wireshark.org/libpcap
Wireshark/TShark uses libpcap to capture live network data.

Installed usually by default on UNIX: `dpkg -s libpcap-dev`

Two Windows versions of libpcap are available. The older one is named [WinPcap](https://wiki.wireshark.org/WinPcap); it is no longer actively being maintained, and is based on an older version of libpcap. The newer one is called [Npcap](https://nmap.org/npcap/)

https://wiki.wireshark.org/Development/LibpcapFileFormat
