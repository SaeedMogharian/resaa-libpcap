//
// Created by Resaa on 11/13/2024.
//
#include <iostream>
#include <unordered_map>
#include <string>
#include <pcap/pcap.h>

using namespace std;

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



class IpStats {
public:
    int packets_sent;
    int bytes_sent;
    string interface;

    // Constructor
    IpStats() : packets_sent(0), bytes_sent(0), interface("") {}

    // Parameterized Constructor
    IpStats(int packets, int bytes, const string& iface)
        : packets_sent(packets), bytes_sent(bytes), interface(iface) {}
};

class StatisticsManager {
private:
    unordered_map<string, IpStats> ip_statistics;
public:
    // Display all statistics
    void print() const {
        cout << "\nIP Address Statistics:\n";
        cout << left << setw(17) << "IP Address"
                  << setw(15) << "Packets Sent"
                  << setw(12) << "Bytes Sent"
                  << setw(12) << "Interface" << "\n";
        
        for (const auto& entry : ip_statistics) {
            cout << left << setw(17) << entry.first
            << setw(15) << entry.second.packets_sent
            << setw(12) << entry.second.bytes_sent
            << setw(12) << entry.second.interface << "\n";
        }
    }

    void update(const u_char* packet, int packet_size, const string& interface, int linkhdrlen) {
        // Interpret the IP header from the packet
//        linkhdrlen = 14;

        auto* iphdr = reinterpret_cast<const struct ip*>(packet + linkhdrlen);

        // Convert the source IP to a string
        string src_ip = inet_ntoa(iphdr->ip_src);

        // Update statistics
        auto& stats = ip_statistics[src_ip];
        stats.packets_sent++;
        stats.bytes_sent += packet_size;
        stats.interface = interface;
    }
}

class StreamHandler {
private:
    string interface_name;
    unique_ptr<pcap_t, decltype(&pcap_close)> injection_handle;
    StatisticsManager& stats_manager;
    int injection_failures = 0;
    int packets_processed = 0;

    PacketHandler(unique_ptr<pcap_t, decltype(&pcap_close)> injectionHandle,
                  const string& interface,
                  StatisticsManager& stats,
                  int linkHeaderLen)
        : injection_handle(move(injectionHandle)),
          interface_name(interface),
          stats_manager(stats),
          {}