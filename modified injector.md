To add an output in the report that shows the result of the injection, we need to enhance the code to identify and log any "injected" packets, alongside the standard packet statistics. Assuming "injected" packets are identified by a specific characteristic (e.g., a unique IP, port, or flag), we can add an additional log entry for these packets.

Here's how to modify the code to include a report on injected packets:

1. Define an indicator for injected packets within `packet_handler()`.
2. Track statistics for injected packets.
3. Display the result of injected packets within `print_ip_statistics()` or in a separate function.

The following modified code snippet includes these changes:

```c
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

// Structure to track injected packets statistics
struct InjectedStats {
    int injected_packets;
    int injected_bytes;
};

struct InjectedStats injected_stats = {0, 0}; // Initialize injected stats

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


pcap_t* create_pcap_handle(char* device, char* filter) {
    // [Code remains the same as in original]
}

void get_link_header_len(pcap_t* handle) {
    // [Code remains the same as in original]
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

    // Check for injected packet condition
    if (strcmp(srcip, "INJECTION_IP") == 0 || strcmp(dstip, "INJECTION_IP") == 0) {
        injected_stats.injected_packets += 1;
        injected_stats.injected_bytes += packet_size;
    }

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

    // Print injected packet statistics
    printf("\nInjected Packet Statistics:\n");
    printf("Injected Packets: %d\n", injected_stats.injected_packets);
    printf("Injected Bytes: %d\n", injected_stats.injected_bytes);
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

int main(int argc, char *argv[]) {
    // [Code remains the same as in original]
}
```

### Explanation of Modifications

- **Injected Packet Condition**: In `packet_handler()`, we check if either the source or destination IP matches `"INJECTION_IP"`, the designated IP for identifying injected packets. Replace `"INJECTION_IP"` with the actual IP address you want to mark as "injected".
  
- **Injected Stats Struct**: We created a `InjectedStats` struct to track `injected_packets` and `injected_bytes`, incremented each time an injected packet is detected.

- **Output in Report**: In `print_ip_statistics()`, we added a section to print the statistics of injected packets after displaying the general IP statistics.

This code addition enables the program to log both the overall packet information and detailed statistics of any injected packets.