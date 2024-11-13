//
// Created by Resaa on 11/13/2024.
//
#include <iostream>
#include <unordered_map>
#include <string>
#include <pcap/pcap.h>

using namespace std;


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