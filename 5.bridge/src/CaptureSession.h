#ifndef CAPTURESESSION_H
#define CAPTURESESSION_H

#include <pcap/pcap.h>
#include <memory>
#include <string>
#include "PacketHandler.h"

/**
 * Represents a network packet capture session on a specific interface.
 * Responsible for setting up the pcap handle, applying filters, and managing packet capture.
 */
class CaptureSession {
private:
    std::string interface_name;  // Name of the network interface for capture
    std::unique_ptr<pcap_t, decltype(&pcap_close)> sniff_handle; // Smart pointer for the pcap handle
    PacketHandler packet_handler; // Handles processing of packets
    int link_header_length = 0;   // Length of the link-layer header
    volatile bool stop_flag = false; // Flag to indicate when the capture should stop

public:
    /**
     * Constructor to initialize a capture session.
     * @param interface The network interface to capture packets on.
     * @param filter The BPF filter to apply to the capture session.
     * @param handler The PacketHandler for processing captured packets.
     */
    CaptureSession(const std::string& interface, const std::string& filter, PacketHandler handler);

    /**
     * Starts the packet capture loop.
     * @param packet_count Number of packets to capture (0 for infinite). This only workd on passive mode
     */
    void startCapture(int packet_count = 0);

    /**
     * Stops the packet capture loop.
     */
    void stopCapture();

    /**
     * Creates a pcap handle for capturing packets on a specified interface.
     * @param device The network interface to open for packet capture.
     * @param filter The BPF filter to apply.
     * @return A raw pointer to the created pcap handle, or nullptr on failure.
     */
    static pcap_t* createPcapHandle(const std::string& device, const std::string& filter);

    /**
     * Retrieves statistics about the capture session.
     * @param stats A reference to a pcap_stat structure to store statistics.
     * @return True if statistics were successfully retrieved, false otherwise.
     */
    bool getStats(struct pcap_stat& stats) const;

    /**
     * Gets the name of the network interface associated with this session.
     * @return The name of the network interface.
     */
    const std::string& getInterfaceName() const;

    /**
     * Gets the PacketHandler associated with this session.
     * @return A reference to the PacketHandler object.
     */
    PacketHandler& getPacketHandler();
};

#endif // CAPTURESESSION_H
