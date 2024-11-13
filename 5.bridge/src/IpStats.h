#ifndef IPSTATS_H
#define IPSTATS_H

#include <string>

class IpStats {
public:
    int packets_sent;
    int bytes_sent;
    std::string interface;

    IpStats();
    IpStats(int packets, int bytes, const std::string& iface);
};

#endif // IPSTATS_H
