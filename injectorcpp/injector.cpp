#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <csignal>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <memory>
#include <iomanip>

struct IpStats {
    int packets_received = 0;
    int packets_sent = 0;
    int bytes_received = 0;
    int bytes_sent = 0;
};

struct InjectionReport {
    std::string src_interface;
    std::string dst_interface;
    std::string src_ip;
    std::string dst_ip;
    bool success;
};

std::unordered_map<std::string, IpStats> ip_statistics;
std::vector<InjectionReport> injection_reports;

// Global variables for interface names
std::string sniff_interface;
std::string inject_interface;

std::unique_ptr<pcap_t, decltype(&pcap_close)> handle_sniff(nullptr, pcap_close);
std::unique_ptr<pcap_t, decltype(&pcap_close)> handle_inject(nullptr, pcap_close);
int linkhdrlen = 0;
int packets = 0;

pcap_t* create_pcap_handle(std::string& device, const std::string& filter);

void get_link_header_len(pcap_t* handle);

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {
    struct ip* iphdr;
    char srcip[INET_ADDRSTRLEN], dstip[INET_ADDRSTRLEN];
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;

    inet_ntop(AF_INET, &iphdr->ip_src, srcip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iphdr->ip_dst, dstip, INET_ADDRSTRLEN);
    int packet_size = packethdr->len;

    ip_statistics[srcip].packets_sent++;
    ip_statistics[srcip].bytes_sent += packet_size;
    ip_statistics[dstip].packets_received++;
    ip_statistics[dstip].bytes_received += packet_size;

    packets++;
    
    // Attempt to inject the packet and log the result
    bool injection_success = (pcap_inject(handle_inject.get(), packetptr - linkhdrlen, packet_size) != PCAP_ERROR);
    if (!injection_success) {
        std::cerr << "pcap_inject failed: " << pcap_geterr(handle_inject.get()) << std::endl;
    }
    
    // Add injection report with actual interface names
    injection_reports.push_back({
        .src_interface = sniff_interface,
        .dst_interface = inject_interface,
        .src_ip = srcip,
        .dst_ip = dstip,
        .success = injection_success
    });
}

void print_ip_statistics() {
    std::cout << "\nIP Address Statistics:\n";
    std::cout << std::left << std::setw(17) << "IP Address"
              << std::setw(15) << "Packets Sent"
              << std::setw(12) << "Bytes Sent"
              << std::setw(18) << "Packets Received"
              << "Bytes Received\n";
    
    for (const auto& [ip, stats] : ip_statistics) {
        std::cout << std::left << std::setw(17) << ip
                  << std::setw(15) << stats.packets_sent
                  << std::setw(12) << stats.bytes_sent
                  << std::setw(18) << stats.packets_received
                  << stats.bytes_received << "\n";
    }
}

void print_injection_report() {
    std::cout << "\nPacket Injection Report:\n";
    std::cout << std::left << std::setw(15) << "Src Interface"
              << std::setw(15) << "Dst Interface"
              << std::setw(16) << "Src IP"
              << std::setw(16) << "Dst IP"
              << "Success\n";
    
    for (const auto& report : injection_reports) {
        std::cout << std::left << std::setw(15) << report.src_interface
                  << std::setw(15) << report.dst_interface
                  << std::setw(16) << report.src_ip
                  << std::setw(16) << report.dst_ip
                  << (report.success ? "Yes" : "No") << "\n";
    }
}

void stop_capture(int signo) {
    struct pcap_stat stats;
    if (pcap_stats(handle_sniff.get(), &stats) >= 0) {
        std::cout << "\n" << packets << " packets captured\n"
                  << stats.ps_recv << " packets received by filter\n"
                  << stats.ps_drop << " packets dropped\n\n";
    }
    print_ip_statistics();
    print_injection_report();
    exit(0);
}

int main(int argc, char *argv[]) {
    int count = 0;
    int opt;

    while ((opt = getopt(argc, argv, "hi:j:n:")) != -1) {
        switch (opt) {
            case 'h':
                std::cout << "usage: " << argv[0] << " [-h] [-i interface_sniff] [-j interface_inject] [-n count] [BPF expression]\n";
                return 0;
            case 'i':
                sniff_interface = optarg;
                break;
            case 'j':
                inject_interface = optarg;
                break;
            case 'n':
                count = std::stoi(optarg);
                break;
        }
    }

    // Concatenate remaining command-line arguments to form the filter
    std::string filter;
    for (int i = optind; i < argc; i++) {
        filter += argv[i];
        filter += " ";
    }

    signal(SIGINT, stop_capture);
    signal(SIGTERM, stop_capture);
    signal(SIGQUIT, stop_capture);

    // Create packet capture handle for sniffing
    handle_sniff.reset(create_pcap_handle(sniff_interface, filter));
    if (!handle_sniff) return -1;

    // Create packet injection handle for injecting
    handle_inject.reset(create_pcap_handle(inject_interface, ""));
    if (!handle_inject) return -1;

    // Get the type of link layer
    get_link_header_len(handle_sniff.get());
    if (linkhdrlen == 0) return -1;

    // Start packet capture
    if (pcap_loop(handle_sniff.get(), count, packet_handler, nullptr) == PCAP_ERROR) {
        std::cerr << "pcap_loop failed: " << pcap_geterr(handle_sniff.get()) << std::endl;
        return -1;
    }

    stop_capture(0);
}

pcap_t* create_pcap_handle(std::string& device, const std::string& filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;
    bpf_u_int32 netmask, srcip;

    if (device.empty()) {
        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf)) {
            std::cerr << "pcap_findalldevs(): " << errbuf << std::endl;
            return nullptr;
        }
        device = alldevs[0].name;
    }

    if (pcap_lookupnet(device.c_str(), &srcip, &netmask, errbuf) == PCAP_ERROR) {
        std::cerr << "pcap_lookupnet: " << errbuf << std::endl;
        return nullptr;
    }

    pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live(): " << errbuf << std::endl;
        return nullptr;
    }

    if (pcap_compile(handle, &bpf, filter.c_str(), 1, netmask) == PCAP_ERROR) {
        std::cerr << "pcap_compile(): " << pcap_geterr(handle) << std::endl;
        return nullptr;
    }

    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        std::cerr << "pcap_setfilter(): " << pcap_geterr(handle) << std::endl;
        return nullptr;
    }

    return handle;
}

void get_link_header_len(pcap_t* handle) {
    int linktype = pcap_datalink(handle);
    if (linktype == PCAP_ERROR) {
        std::cerr << "pcap_datalink(): " << pcap_geterr(handle) << std::endl;
        return;
    }

    switch (linktype) {
        case DLT_NULL: linkhdrlen = 4; break;
        case DLT_EN10MB: linkhdrlen = 14; break;
        case DLT_SLIP:
        case DLT_PPP: linkhdrlen = 24; break;
        default: linkhdrlen = 0;
    }
}
