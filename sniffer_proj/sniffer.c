/*
   sniffer.c

   Example packet sniffer using the libpcap packet capture library available
   from http://www.tcpdump.org.
  
   ------------------------------------------

   Copyright (c) 2012 Vic Hargrave

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


struct IpStats {
    char ip[INET_ADDRSTRLEN];
    int packets_received;
    int packets_sent;
    int bytes_received;
    int bytes_sent;
    struct IpStats* next;
};

// Map to store IP statistics
// Head of the linked list
struct IpStats* ip_statistics = NULL;

pcap_t* handle;
int linkhdrlen;
int packets;


// Function to find or add an IP in the statistics list
struct IpStats* find_or_add_ip(const char* ip) {
    struct IpStats* current = ip_statistics;
    struct IpStats* prev = NULL;

    // Search for the IP in the list
    while (current != NULL) {
        if (strcmp(current->ip, ip) == 0) {
            return current;
        }
        prev = current;
        current = current->next;
    }

    // IP not found; add a new node to the list
    struct IpStats* new_entry = (struct IpStats*)malloc(sizeof(struct IpStats));
    strcpy(new_entry->ip, ip);
    new_entry->packets_received = 0;
    new_entry->packets_sent = 0;
    new_entry->bytes_received = 0;
    new_entry->bytes_sent = 0;
    new_entry->next = NULL;

    // Add to the list
    if (prev == NULL) {
        ip_statistics = new_entry; // First element
    } else {
        prev->next = new_entry;
    }

    return new_entry;
}


pcap_t* create_pcap_handle(char* device, char* filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_if_t* devices = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;

    // If no network interface (device) is specfied, get the first one.
    if (!*device) {
    	if (pcap_findalldevs(&devices, errbuf)) {
            fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
            return NULL;
        }
        strcpy(device, devices[0].name);
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Open the device for live capture.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(handle, &bpf, filter, 1, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    // Bind the packet filter to the libpcap handle.    
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    return handle;
}

void get_link_header_len(pcap_t* handle)
{
    int linktype;
 
    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        printf("pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }
 
    // Set the datalink layer header size.
    switch (linktype)
    {
    case DLT_NULL:
        linkhdrlen = 4;
        break;
 
    case DLT_EN10MB:
        linkhdrlen = 14;
        break;
 
    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;
 
    default:
        printf("Unsupported datalink (%d)\n", linktype);
        linkhdrlen = 0;
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {
    struct ip* iphdr;
    char srcip[INET_ADDRSTRLEN];
    char dstip[INET_ADDRSTRLEN];

    // Skip the datalink layer header and get the IP header fields
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;

    // Get source and destination IP addresses as strings
    inet_ntop(AF_INET, &iphdr->ip_src, srcip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iphdr->ip_dst, dstip, INET_ADDRSTRLEN);
    int packet_size = packethdr->len;

    // Find or add source IP and update sent stats
    struct IpStats* src_stats = find_or_add_ip(srcip);
    src_stats->packets_sent += 1;
    src_stats->bytes_sent += packet_size;

    // Find or add destination IP and update received stats
    struct IpStats* dst_stats = find_or_add_ip(dstip);
    dst_stats->packets_received += 1;
    dst_stats->bytes_received += packet_size;

    packets += 1; // Increment total packet count
}

// Function to print IP statistics
void print_ip_statistics() {
    printf("\nIP Address Statistics:\n");
    printf("%-15s %-10s %-10s %-10s %-10s\n", "IP Address", "Packets Sent", "Bytes Sent", "Packets Received", "Bytes Received");

    struct IpStats* current = ip_statistics;
    while (current != NULL) {
        printf("%-15s %-10d %-10d %-10d %-10d\n", current->ip, current->packets_sent, current->bytes_sent, current->packets_received, current->bytes_received);
        current = current->next;
    }
}

// Free linked list memory
void free_ip_statistics() {
    struct IpStats* current = ip_statistics;
    while (current != NULL) {
        struct IpStats* next = current->next;
        free(current);
        current = next;
    }
}

// Modify stop_capture to display statistics before exiting
void stop_capture(int signo) {
    struct pcap_stat stats;

    if (pcap_stats(handle, &stats) >= 0) {
        printf("\n%d packets captured\n", packets);
        printf("%d packets received by filter\n", stats.ps_recv); 
        printf("%d packets dropped\n\n", stats.ps_drop);
    }

    // Print IP statistics
    print_ip_statistics();

    // Free the linked list memory
    free_ip_statistics();

    pcap_close(handle);
    exit(0);
}

int main(int argc, char *argv[])
{
    char device[256];
    char filter[256]; 
    int count = 0;
    int opt;

    *device = 0;
    *filter = 0;

    // Get the command line options, if any
    while ((opt = getopt(argc, argv, "hi:n:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            printf("usage: %s [-h] [-i interface] [-n count] [BPF expression]\n", argv[0]);
            exit(0);
            break;
        case 'i':
            strcpy(device, optarg);
            break;
        case 'n':
            count = atoi(optarg);
            break;
        }
    }

    // Get the packet capture filter expression, if any.
    for (int i = optind; i < argc; i++) {
        strcat(filter, argv[i]);
        strcat(filter, " ");
    }

    signal(SIGINT, stop_capture);
    signal(SIGTERM, stop_capture);
    signal(SIGQUIT, stop_capture);
    
    // Create packet capture handle.
    handle = create_pcap_handle(device, filter);
    if (handle == NULL) {
        return -1;
    }

    // Get the type of link layer.
    get_link_header_len(handle);
    if (linkhdrlen == 0) {
        return -1;
    }

    // Start the packet capture with a set count or continually if the count is 0.
    if (pcap_loop(handle, count, packet_handler, (u_char*)NULL) == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    stop_capture(0);
}
