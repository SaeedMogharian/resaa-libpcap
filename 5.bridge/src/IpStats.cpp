#include "IpStats.h"

IpStats::IpStats() : packets_sent(0), bytes_sent(0), interface("") {}

IpStats::IpStats(int packets, int bytes, const std::string& iface)
    : packets_sent(packets), bytes_sent(bytes), interface(iface) {}
