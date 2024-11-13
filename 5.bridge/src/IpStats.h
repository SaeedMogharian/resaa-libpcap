#ifndef IPSTATS_H
#define IPSTATS_H

#include <string>

/**
 * Stores statistics for an individual IP address, such as the number
 * of packets and bytes sent, along with the associated interface.
 */
class IpStats {
public:
    int packets_sent;      // Number of packets sent from this IP address
    int bytes_sent;        // Total bytes sent from this IP address
    std::string interface; // The interface through which the packets were sent

    /**
     * Default constructor to initialize an empty IpStats object.
     */
    IpStats();

    /**
     * Parameterized constructor to initialize IpStats with specific values.
     * @param packets Number of packets sent.
     * @param bytes Total bytes sent.
     * @param iface Name of the associated network interface.
     */
    IpStats(int packets, int bytes, const std::string& iface);
};

#endif // IPSTATS_H
