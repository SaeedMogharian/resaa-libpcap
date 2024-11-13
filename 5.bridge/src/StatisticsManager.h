#ifndef STATISTICSMANAGER_H
#define STATISTICSMANAGER_H

#include <unordered_map>
#include <string>
#include <iostream>
#include <iomanip>
#include "IpStats.h"

/**
 * Manages IP-based statistics for captured packets, such as the number of packets
 * and bytes sent from each source IP address.
 */
class StatisticsManager {
private:
    std::unordered_map<std::string, IpStats> ip_statistics; // Maps IP addresses to statistics

public:
    /**
     * Updates the statistics for a captured packet.
     * @param packet The raw packet data.
     * @param packet_size The size of the packet in bytes.
     * @param interface The name of the network interface the packet was captured on.
     * @param link_header_length The length of the link-layer header.
     */
    void update(const u_char* packet, int packet_size, const std::string& interface, int link_header_length);

    /**
     * Prints the collected IP statistics in a tabular format.
     */
    void print() const;
};

#endif // STATISTICSMANAGER_H
