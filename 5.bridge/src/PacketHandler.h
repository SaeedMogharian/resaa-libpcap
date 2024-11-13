#ifndef PACKETHANDLER_H
#define PACKETHANDLER_H

#include <pcap/pcap.h>
#include <memory>
#include <string>
#include "StatisticsManager.h"

class PacketHandler {
private:
    std::unique_ptr<pcap_t, decltype(&pcap_close)> injection_handle;
    std::string interface_name;
    StatisticsManager& stats_manager;
    int injection_failures = 0;
    int packets_processed = 0;

public:
    PacketHandler(std::unique_ptr<pcap_t, decltype(&pcap_close)> injectionHandle,
                  const std::string& interface,
                  StatisticsManager& stats);

    static void packetCallback(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt);

    void handle(const struct pcap_pkthdr* packethdr, const u_char* packetptr, int link_header_length);
    void printInjectionStatistics() const;
    int getPacketsProcessed() const;
};

#endif // PACKETHANDLER_H
