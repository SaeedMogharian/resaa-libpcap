#ifndef CAPTURESESSION_H
#define CAPTURESESSION_H

#include <pcap/pcap.h>
#include <memory>
#include <string>
#include "PacketHandler.h"

class CaptureSession {
private:
    std::string interface_name;
    std::unique_ptr<pcap_t, decltype(&pcap_close)> sniff_handle;
    PacketHandler packet_handler;
    int link_header_length = 0; // Store the link-layer header length
    volatile bool stop_flag = false;

public:
    CaptureSession(const std::string& interface, const std::string& filter, PacketHandler handler);

    void startCapture(int packet_count = 0);
    void stopCapture();
    static pcap_t* createPcapHandle(const std::string& device, const std::string& filter);
    bool getStats(struct pcap_stat& stats) const;
    const std::string& getInterfaceName() const;
    PacketHandler& getPacketHandler();

    int getLinkHeaderLength() const; // New accessor for link header length
};

#endif // CAPTURESESSION_H
