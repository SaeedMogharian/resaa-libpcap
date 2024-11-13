#include "StatisticsManager.h"
#include <netinet/ip.h>
#include <arpa/inet.h>

void StatisticsManager::update(const u_char* packet, int packet_size, const std::string& interface, int link_header_length) {
    auto* iphdr = reinterpret_cast<const struct ip*>(packet + link_header_length);

    std::string src_ip = inet_ntoa(iphdr->ip_src);

    auto& stats = ip_statistics[src_ip];
    stats.packets_sent++;
    stats.bytes_sent += packet_size;
    stats.interface = interface;
}

void StatisticsManager::print() const {
    std::cout << "\nIP Address Statistics:\n";
    std::cout << std::left << std::setw(17) << "IP Address"
              << std::setw(15) << "Packets Sent"
              << std::setw(12) << "Bytes Sent"
              << std::setw(12) << "Interface" << "\n";

    for (const auto& [ip, stats] : ip_statistics) {
        std::cout << std::left
                  << std::setw(17) << ip
                  << std::setw(15) << stats.packets_sent
                  << std::setw(12) << stats.bytes_sent
                  << std::setw(12) << stats.interface << "\n";
    }
}
