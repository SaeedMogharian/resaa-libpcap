#include <iostream>
#include <string>
#include <unordered_map>
#include <csignal>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <memory>
#include <iomanip>
#include <thread>
#include <vector>


// Forward declarations
class PacketHandler;
class StatisticsManager;
class CaptureSession;

// Statistics Manager
class StatisticsManager {
private:
    struct IpStats {
        int packets_sent = 0;
        int bytes_sent = 0;
        std::string interface;
    };
    std::unordered_map<std::string, IpStats> ip_statistics;

public:
    void update(const u_char* packet, int packet_size, const std::string& interface, int linkhdrlen) {
        struct ip* iphdr = (struct ip*)(packet + linkhdrlen);
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iphdr->ip_src, src_ip, INET_ADDRSTRLEN);

        auto& stats = ip_statistics[src_ip];
        stats.packets_sent++;
        stats.bytes_sent += packet_size;
        stats.interface = interface;
    }

    void print() const {
        std::cout << "\nIP Address Statistics:\n";
        std::cout << std::left << std::setw(17) << "IP Address"
                  << std::setw(15) << "Packets Sent"
                  << std::setw(12) << "Bytes Sent"
                  << std::setw(12) << "Interface" << "\n";

        for (const auto& [ip, stats] : ip_statistics) {
            std::cout << std::left << std::setw(17) << ip
                      << std::setw(15) << stats.packets_sent
                      << std::setw(12) << stats.bytes_sent
                      << std::setw(12) << stats.interface << "\n";
        }
    }
};

// Packet Handler
class PacketHandler {
private:
    pcap_t* injection_handle;
    std::string interface_name;
    StatisticsManager& stats_manager;
    int linkhdrlen;
    int injection_failures = 0;
    int packets_processed = 0;

public:
    PacketHandler(pcap_t* injectionHandle, const std::string& interface, StatisticsManager& stats, int linkHeaderLen)
        : injection_handle(injectionHandle), interface_name(interface), stats_manager(stats), linkhdrlen(linkHeaderLen) {}

    void handle(const struct pcap_pkthdr* header, const u_char* packet) {
        packets_processed++;
        if (pcap_inject(injection_handle, packet, header->len) == PCAP_ERROR) {
            std::cerr << "Failed to inject packet on interface " << interface_name << ": " << pcap_geterr(injection_handle) << std::endl;
            injection_failures++;
        }
        stats_manager.update(packet, header->len, interface_name, linkhdrlen);
    }

    void printInjectionStats() const {
        std::cout << std::left << std::setw(22) << interface_name
                  << std::setw(17) << packets_processed
                  << std::setw(10) << injection_failures
                  << std::fixed << std::setprecision(2)
                  << (packets_processed > 0
                          ? (100.0 * (packets_processed - injection_failures) / packets_processed)
                          : 0.0)
                  << "%\n";
    }
};

// Capture Session
class CaptureSession {
private:
    std::string interface_name;
    std::unique_ptr<pcap_t, decltype(&pcap_close)> sniff_handle;
    PacketHandler packet_handler;
    int linkhdrlen;

    void calculateLinkHeaderLength() {
        int linktype = pcap_datalink(sniff_handle.get());
        if (linktype == DLT_NULL) linkhdrlen = 4;
        else if (linktype == DLT_EN10MB) linkhdrlen = 14;
        else if (linktype == DLT_SLIP || linktype == DLT_PPP) linkhdrlen = 24;
        else linkhdrlen = 0;
    }

public:
    CaptureSession(const std::string& interface, const std::string& filter, PacketHandler handler)
        : interface_name(interface),
          sniff_handle(nullptr, pcap_close),
          packet_handler(std::move(handler)),
          linkhdrlen(0) {
        sniff_handle.reset(createPcapHandle(interface, filter));
        calculateLinkHeaderLength();
    }

    void startCapture(int packet_count = 0) {
        if (pcap_loop(sniff_handle.get(), packet_count,
                    [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
                        reinterpret_cast<PacketHandler*>(user)->handle(hdr, pkt);
                    },
                    reinterpret_cast<u_char*>(&packet_handler)) == PCAP_ERROR) {
            std::cerr << "pcap_loop failed on interface " << interface_name << ": " << pcap_geterr(sniff_handle.get()) << std::endl;
        }
    }


    static pcap_t* createPcapHandle(const std::string& device, const std::string& filter) {
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program bpf;
        bpf_u_int32 netmask, srcip;

        if (pcap_lookupnet(device.c_str(), &srcip, &netmask, errbuf) == PCAP_ERROR) {
            std::cerr << "pcap_lookupnet: " << errbuf << std::endl;
            return nullptr;
        }

        pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "pcap_open_live(): " << errbuf << std::endl;
            return nullptr;
        }

        if (!filter.empty()) {
            if (pcap_compile(handle, &bpf, filter.c_str(), 1, netmask) == PCAP_ERROR ||
                pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
                std::cerr << "pcap_setfilter(): " << pcap_geterr(handle) << std::endl;
                pcap_close(handle);
                return nullptr;
            }
        }

        return handle;
    }
};

// Main Application
class Application {
private:
    std::string interface_prim;
    std::string interface_secn;
    StatisticsManager stats_manager;

public:
    void run(int argc, char* argv[]) {
        // Parse command-line arguments
        parseArguments(argc, argv);

        // Create session and handlers
        CaptureSession primarySession(interface_prim, "", PacketHandler(nullptr, interface_prim, stats_manager, 0));

        if (!interface_secn.empty()) {
            CaptureSession secondarySession(interface_secn, "", PacketHandler(nullptr, interface_secn, stats_manager, 0));
            std::thread sec_thread(&CaptureSession::startCapture, &secondarySession, 0);
            sec_thread.join();
        }

        std::thread prim_thread(&CaptureSession::startCapture, &primarySession, 0);
        prim_thread.join();

        stats_manager.print();
    }

    void parseArguments(int argc, char* argv[]) {
        int opt;
        while ((opt = getopt(argc, argv, "hi:j:")) != -1) {
            switch (opt) {
                case 'i':
                    interface_prim = optarg;
                    break;
                case 'j':
                    interface_secn = optarg;
                    break;
                default:
                    std::cerr << "Usage: " << argv[0] << " -i <interface> -j <interface>\n";
                    exit(EXIT_FAILURE);
            }
        }
    }
};

int main(int argc, char* argv[]) {
    Application app;
    app.run(argc, argv);
    return 0;
}
