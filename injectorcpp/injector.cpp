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
// InjectionStat interface_a_stats;
// InjectionStat interface_b_stats;

// Global variables for interface names
std::string interface_a;
std::string interface_b;


std::unique_ptr<pcap_t, decltype(&pcap_close)> handle_sniff_a(nullptr, pcap_close);
std::unique_ptr<pcap_t, decltype(&pcap_close)> handle_inject_a(nullptr, pcap_close);
std::unique_ptr<pcap_t, decltype(&pcap_close)> handle_sniff_b(nullptr, pcap_close);
std::unique_ptr<pcap_t, decltype(&pcap_close)> handle_inject_b(nullptr, pcap_close);
int linkhdrlen = 0;
int packets_a = 0;
int packets_b = 0;
int injection_failures_a = 0;
int injection_failures_b = 0;

pcap_t* create_pcap_handle(std::string& device, const std::string& filter);

void get_link_header_len(pcap_t* handle);


void update_ip_statistics(const u_char* packet, int packet_size, const std::string& interface) {
    struct ip* iphdr = (struct ip*)(packet + linkhdrlen);
    char dstip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iphdr->ip_dst, dstip, INET_ADDRSTRLEN);

    auto& stats = ip_statistics[dstip];
    stats.packets_sent++;
    stats.bytes_sent += packet_size;
    stats.interface = interface; // Store the interface
}


void packet_handler_a (u_char* user, const struct pcap_pkthdr* packethdr, const u_char* packetptr) {
    
    packets_a++;


    // const std::string interface = "interface_a"; // Mark the source interface
    bool injection_success = (pcap_inject(handle_inject_b.get(), packetptr, packethdr->len) != PCAP_ERROR);
    if (!injection_success) {
        std::cerr << "Failed to inject packet from A to B: " << pcap_geterr(handle_inject_b.get()) << std::endl;
        injection_failures_a++;
    }

    // Update IP statistics (example)
    update_ip_statistics(packetptr, packethdr->len, interface_a);
};

void packet_handler_b (u_char* user, const struct pcap_pkthdr* packethdr, const u_char* packetptr) {
  
    packets_b++;


    // const std::string interface = "interface_a"; // Mark the source interface
    bool injection_success = (pcap_inject(handle_inject_a.get(), packetptr, packethdr->len) != PCAP_ERROR);
    if (!injection_success) {
        std::cerr << "Failed to inject packet from B to A: " << pcap_geterr(handle_inject_a.get()) << std::endl;
        injection_failures_b++;
    }

    // Update IP statistics (example)
    update_ip_statistics(packetptr, packethdr->len, interface_b);
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
              << std::setw(20) << "Received On Interface"
              << std::setw(15) << "Packets Injected"
              << std::setw(15) << "Failures"
              << "Success Rate (%)\n";

    // Print statistics for each interface
    std::cout << std::left 
              << std::setw(20) << interface_a
              << std::setw(15) << packets_a
              << std::setw(15) << injection_failures_a
              << std::fixed << std::setprecision(2)
              << (packets_a > 0 
                  ? (100.0 * (packets_a - injection_failures_a) / packets_a) 
                  : 0.0)
              << "%\n";
    std::cout << std::left 
              << std::setw(20) << interface_b
              << std::setw(15) << packets_b
              << std::setw(15) << injection_failures_b
              << std::fixed << std::setprecision(2)
              << (packets_b > 0 
                  ? (100.0 * (packets_b - injection_failures_b) / packets_b) 
                  : 0.0)
              << "%\n";
}


void stop_capture(int signo) {
    struct pcap_stat stats;
    if (pcap_stats(handle_sniff_a.get(), &stats) >= 0) {
        std::cout << "\n"
                  << interface_a << ":\n"
                  << packets_a << " packets captured\n"
                  << stats.ps_recv << " packets received by filter\n"
                  << stats.ps_drop << " packets dropped\n\n";
    }
    if (pcap_stats(handle_sniff_b.get(), &stats) >= 0) {
        std::cout << "\n"
                  << interface_b << ":\n"
                  << packets_b << " packets captured\n"
                  << stats.ps_recv << " packets received by filter\n"
                  << stats.ps_drop << " packets dropped\n\n";
    }
    print_ip_statistics();
    print_injection_statistics();
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
                interface_a = optarg;
                break;
            case 'j':
                interface_b = optarg;
                break;
            case 'n':
                count = std::stoi(optarg);
                break;
        }
    }

    if (interface_a.empty() || interface_b.empty()) {
        std::cerr << "Both -i and -j options must be specified.\n";
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
    handle_sniff_a.reset(create_pcap_handle(interface_a, filter));
    handle_sniff_b.reset(create_pcap_handle(interface_b, filter));

    if (!handle_sniff_a || !handle_sniff_b) return -1;

    // Create packet injection handles for both interfaces
    handle_inject_a.reset(create_pcap_handle(interface_a, ""));
    handle_inject_b.reset(create_pcap_handle(interface_b, ""));

    if (!handle_inject_a || !handle_inject_b) return -1;

    // Get the type of link layer for both sniffing interfaces
    get_link_header_len(handle_sniff_a.get());
    if (linkhdrlen == 0) return -1;

    // Define lambda functions for packet handling
    // auto packet_handler_a = [&](u_char* user, const struct pcap_pkthdr* packethdr, const u_char* packetptr) {
    //     if (pcap_inject(handle_inject_b.get(), packetptr, packethdr->len) == PCAP_ERROR) {
    //         std::cerr << "Failed to inject packet from A to B: " << pcap_geterr(handle_inject_b.get()) << std::endl;
    //     }
    // };

    // auto packet_handler_b = [&](u_char* user, const struct pcap_pkthdr* packethdr, const u_char* packetptr) {
    //     if (pcap_inject(handle_inject_a.get(), packetptr, packethdr->len) == PCAP_ERROR) {
    //         std::cerr << "Failed to inject packet from B to A: " << pcap_geterr(handle_inject_a.get()) << std::endl;
    //     }
    // };

    // Start packet capture on both interfaces using threads
    std::thread sniff_a([&]() {
        if (pcap_loop(handle_sniff_a.get(), count, [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
            (*(decltype(packet_handler_a)*)user)(nullptr, hdr, pkt);
        }, (u_char*)&packet_handler_a) == PCAP_ERROR) {
            std::cerr << "pcap_loop failed on interface A: " << pcap_geterr(handle_sniff_a.get()) << std::endl;
        }
    });

    std::thread sniff_b([&]() {
        if (pcap_loop(handle_sniff_b.get(), count, [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
            (*(decltype(packet_handler_b)*)user)(nullptr, hdr, pkt);
        }, (u_char*)&packet_handler_b) == PCAP_ERROR) {
            std::cerr << "pcap_loop failed on interface B: " << pcap_geterr(handle_sniff_b.get()) << std::endl;
        }
    });

    sniff_a.join();
    sniff_b.join();

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
