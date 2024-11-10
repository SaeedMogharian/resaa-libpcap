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
#include <thread>

struct IpStats {
    int packets_sent = 0;
    int bytes_sent = 0;
    std::string interface;
};

std::unordered_map<std::string, IpStats> ip_statistics;

// // Global variables for interface names
// InjectionStat interface_prim_stats;
// InjectionStat interface_secn_stats;

// Global variables for interface names
std::string interface_prim;
std::string interface_secn;
int packets_prim = 0;
int packets_secn = 0;
int injection_failures_prim = 0;
int injection_failures_secn = 0;


std::unique_ptr<pcap_t, decltype(&pcap_close)> handle_sniff_prim(nullptr, pcap_close);
std::unique_ptr<pcap_t, decltype(&pcap_close)> handle_inject_prim(nullptr, pcap_close);
std::unique_ptr<pcap_t, decltype(&pcap_close)> handle_sniff_secn(nullptr, pcap_close);
std::unique_ptr<pcap_t, decltype(&pcap_close)> handle_inject_secn(nullptr, pcap_close);
int linkhdrlen = 0;


pcap_t* create_pcap_handle(std::string& device, const std::string& filter);

void get_link_header_len(pcap_t* handle);

void update_ip_statistics(const u_char* packet, int packet_size, const std::string& interface) {
    struct ip* iphdr = (struct ip*)(packet + linkhdrlen);
    char dstip[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &iphdr->ip_dst, dstip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iphdr->ip_src, dstip, INET_ADDRSTRLEN);

    auto& stats = ip_statistics[dstip];
    stats.packets_sent++;
    stats.bytes_sent += packet_size;
    stats.interface = interface;
}


void packet_handler_prim (u_char* user, const struct pcap_pkthdr* packethdr, const u_char* packetptr) {
    packets_prim++;
    
    if (!interface_secn.empty()){
        bool injection_success = (pcap_inject(handle_inject_secn.get(), packetptr, packethdr->len) != PCAP_ERROR);
        if (!injection_success) {
            std::cerr << "Failed to inject packet from A to B: " << pcap_geterr(handle_inject_secn.get()) << std::endl;
            injection_failures_prim++;
        }
    }

    update_ip_statistics(packetptr, packethdr->len, interface_prim);
};

void packet_handler_secn (u_char* user, const struct pcap_pkthdr* packethdr, const u_char* packetptr) {
    packets_secn++;
    
    bool injection_success = (pcap_inject(handle_inject_prim.get(), packetptr, packethdr->len) != PCAP_ERROR);
    if (!injection_success) {
        std::cerr << "Failed to inject packet from B to A: " << pcap_geterr(handle_inject_prim.get()) << std::endl;
        injection_failures_secn++;
    }

    update_ip_statistics(packetptr, packethdr->len, interface_secn);
};



void print_ip_statistics() {
    std::cout << "\nIP Address Statistics:\n";
    std::cout << std::left 
              << std::setw(17) << "IP Address"
              << std::setw(15) << "Packets Sent"
              << std::setw(12) << "Bytes Sent"
              << std::setw(12) << "Interface"
              << "\n";

    for (const auto& [ip, stats] : ip_statistics) {
        std::cout << std::left 
                  << std::setw(17) << ip
                  << std::setw(15) << stats.packets_sent
                  << std::setw(12) << stats.bytes_sent
                  << std::setw(12) << stats.interface
                  << "\n";
    }
}



void print_injection_statistics() {
    std::cout << "\nInjection Statistics Report:\n";
    std::cout << std::left 
              << std::setw(22) << "ReceivedOnInterface"
              << std::setw(17) << "PacketsInjected"
              << std::setw(10) << "Failures"
              << "SuccessRate (%)\n";

    // Print statistics for each interface
    std::cout << std::left 
              << std::setw(22) << interface_prim
              << std::setw(17) << packets_prim
              << std::setw(10) << injection_failures_prim
              << std::fixed << std::setprecision(2)
              << (packets_prim > 0 
                  ? (100.0 * (packets_prim - injection_failures_prim) / packets_prim) 
                  : 0.0)
              << "%\n";
    std::cout << std::left 
            << std::setw(22) << interface_secn
            << std::setw(17) << packets_secn
            << std::setw(10) << injection_failures_secn
            << std::fixed << std::setprecision(2)
            << (packets_secn > 0 
                ? (100.0 * (packets_secn - injection_failures_secn) / packets_secn) 
                : 0.0)
            << "%\n";

}


void stop_capture(int signo) {
    struct pcap_stat stats;
    if (pcap_stats(handle_sniff_prim.get(), &stats) >= 0) {
        std::cout << "\n"
                  << interface_prim << ":\n"
                  << packets_prim << " packets captured\n"
                  << stats.ps_recv << " packets received by filter\n"
                  << stats.ps_drop << " packets dropped\n\n";
    }
    if (!interface_secn.empty() && pcap_stats(handle_sniff_secn.get(), &stats) >= 0) {
        std::cout << "\n"
                  << interface_secn << ":\n"
                  << packets_secn << " packets captured\n"
                  << stats.ps_recv << " packets received by filter\n"
                  << stats.ps_drop << " packets dropped\n\n";
    }
    print_ip_statistics();
    if (!interface_secn.empty()){
        print_injection_statistics();
    }
    exit(0);
}
int main(int argc, char* argv[]) {
    int count = 0;
    int opt;

    while ((opt = getopt(argc, argv, "hi:j:n:")) != -1) {
        switch (opt) {
            case 'h':
                std::cout << "usage: " << argv[0] << " [-h] [-i interface_sniff] [-j interface_inject] [-n count] [BPF expression]\n";
                return 0;
            case 'i':
                interface_prim = optarg;
                break;
            case 'j':
                interface_secn = optarg;
                break;
            case 'n':
                count = std::stoi(optarg);
                break;
        }
    }

    if (interface_prim.empty()) {
        std::cerr << "At least one interface must be specified using -i.\n";
        return -1;
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

    // Create packet capture handles for both interfaces
    handle_sniff_prim.reset(create_pcap_handle(interface_prim, filter));
    if (!handle_sniff_prim) return -1;

    if (!interface_secn.empty()){
        handle_sniff_secn.reset(create_pcap_handle(interface_secn, filter));
        if (!handle_sniff_secn) return -1;

        // Create packet injection handles for both interfaces
        handle_inject_prim.reset(create_pcap_handle(interface_prim, ""));
        handle_inject_secn.reset(create_pcap_handle(interface_secn, ""));
        if (!handle_inject_prim || !handle_inject_secn) return -1;
    }

    
    // Get the type of link layer for both sniffing interfaces
    get_link_header_len(handle_sniff_prim.get());
    if (linkhdrlen == 0) return -1;

    // Start packet capture on both interfaces using threads
    std::thread sniff_prim([&]() {
        if (pcap_loop(handle_sniff_prim.get(), count, [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
            (*(decltype(packet_handler_prim)*)user)(nullptr, hdr, pkt);
        }, (u_char*)&packet_handler_prim) == PCAP_ERROR) {
            std::cerr << "pcap_loop failed on interface A: " << pcap_geterr(handle_sniff_prim.get()) << std::endl;
        }
    });

    if (!interface_secn.empty()){
        std::thread sniff_secn([&]() {
            if (pcap_loop(handle_sniff_secn.get(), count, [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
                (*(decltype(packet_handler_secn)*)user)(nullptr, hdr, pkt);
            }, (u_char*)&packet_handler_secn) == PCAP_ERROR) {
                std::cerr << "pcap_loop failed on interface B: " << pcap_geterr(handle_sniff_secn.get()) << std::endl;
            }
        });

        sniff_secn.join();
    }

    sniff_prim.join();
    

    stop_capture(0);
    return 0;
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

    if (!filter.empty()) {
        if (pcap_compile(handle, &bpf, filter.c_str(), 1, netmask) == PCAP_ERROR) {
            std::cerr << "pcap_compile(): " << pcap_geterr(handle) << std::endl;
            return nullptr;
        }

        if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
            std::cerr << "pcap_setfilter(): " << pcap_geterr(handle) << std::endl;
            return nullptr;
        }
    }
    
    // Only capture inbound packets (received packets)
    if (pcap_setdirection(handle, PCAP_D_IN) == PCAP_ERROR) {
        std::cerr << "pcap_setdirection(): " << pcap_geterr(handle) << std::endl;
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
