#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    char *net; /* dot notation of the network address */
    char *mask; /* dot notation of the network mask    */
    int ret; /* return code */
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp; /* ip */
    bpf_u_int32 maskp; /* subnet mask */
    struct in_addr addr;
    pcap_if_t *alldevs, *d;

    /* find all devices */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        exit(1);
    }

    /* select the first device */
    d = alldevs;
    if (d == NULL) {
        fprintf(stderr, "No devices found\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }

    printf("DEV: %s\n", d->name);

    /* get the network address and mask */
    ret = pcap_lookupnet(d->name, &netp, &maskp, errbuf);
    if (ret == -1) {
        printf("Error looking up network: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        exit(1);
    }

    /* convert and print network address */
    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (net == NULL) {
        perror("inet_ntoa");
        pcap_freealldevs(alldevs);
        exit(1);
    }
    printf("NET: %s\n", net);

    /* convert and print subnet mask */
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if (mask == NULL) {
        perror("inet_ntoa");
        pcap_freealldevs(alldevs);
        exit(1);
    }
    printf("MASK: %s\n", mask);

    /* free the device list */
    pcap_freealldevs(alldevs);

    return 0;
}
