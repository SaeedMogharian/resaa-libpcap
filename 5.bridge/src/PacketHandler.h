#ifndef PACKETHANDLER_H
#define PACKETHANDLER_H

#include <pcap/pcap.h>
#include <memory>
#include <string>
#include <iostream>
#include "StatisticsManager.h"

/**
 * Handles the processing of captured packets, including forwarding them
 * to another interface and updating statistics.
 */
class PacketHandler {
private:
    std::unique_ptr<pcap_t, decltype(&pcap_close)> injection_handle; // Smart pointer for pcap injection handle
    std::string interface_name;       // Name of the interface this handler is associated with
    StatisticsManager& stats_manager; // Reference to the statistics manager for updating stats
    int injection_failures = 0;       // Number of failed packet injections
    int packets_processed = 0;        // Total number of packets processed

public:
    /**
     * Constructor to initialize the PacketHandler.
     * @param injectionHandle A pcap handle for injecting packets.
     * @param interface The name of the associated network interface.
     * @param stats A reference to the StatisticsManager for updating stats.
     */
    PacketHandler(std::unique_ptr<pcap_t, decltype(&pcap_close)> injectionHandle,
                  const std::string& interface,
                  StatisticsManager& stats);

    /**
     * Static callback function for pcap_loop.
     * @param user Pointer to the PacketHandler object.
     * @param hdr The packet header structure.
     * @param pkt The raw packet data.
     */
    static void packetCallback(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt);

    /**
     * Processes a single captured packet.
     * @param packethdr The packet header.
     * @param packetptr The raw packet data.
     * @param link_header_length The length of the link-layer header.
     */
    void handle(const struct pcap_pkthdr* packethdr, const u_char* packetptr, int link_header_length);

    /**
     * Prints statistics about packet injection failures and successes.
     */
    void print() const;

    /**
     * Gets the total number of packets processed by this handler.
     * @return The number of processed packets.
     */
    int getPacketsProcessed() const;
};

#endif // PACKETHANDLER_H
