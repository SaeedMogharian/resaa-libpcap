#include "PacketHandler.h"

PacketHandler::PacketHandler(std::unique_ptr<pcap_t, decltype(&pcap_close)> injectionHandle,
                             const std::string& interface,
                             StatisticsManager& stats)
    : injection_handle(std::move(injectionHandle)),
      interface_name(interface),
      stats_manager(stats) {}

void PacketHandler::packetCallback(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
    auto* handler = reinterpret_cast<PacketHandler*>(user);
    int link_header_length = 0; // Replace with appropriate logic if needed.
    handler->handle(hdr, pkt, link_header_length);
}

void PacketHandler::handle(const struct pcap_pkthdr* packethdr, const u_char* packetptr, int link_header_length) {
    packets_processed++;
    if (injection_handle && pcap_inject(injection_handle.get(), packetptr, packethdr->len) == PCAP_ERROR) {
        std::cerr << "Failed to inject packet from interface " << interface_name << ": "
                  << pcap_geterr(injection_handle.get()) << "\n";
        injection_failures++;
    }

    stats_manager.update(packetptr, packethdr->len, interface_name, link_header_length);
}

void PacketHandler::printInjectionStatistics() const {
    std::cout << std::left
              << std::setw(22) << interface_name
              << std::setw(17) << packets_processed
              << std::setw(10) << injection_failures
              << (packets_processed > 0
                  ? (100.0 * (packets_processed - injection_failures) / packets_processed)
                  : 0.0)
              << "%\n";
}

int PacketHandler::getPacketsProcessed() const {
    return packets_processed;
}
