#include "CaptureSession.h"
#include "pcap_utils.h"
#include <iostream>

CaptureSession::CaptureSession(const std::string& interface, const std::string& filter, PacketHandler handler)
    : interface_name(interface),
      sniff_handle(nullptr, pcap_close),
      packet_handler(std::move(handler)) {
    sniff_handle.reset(createPcapHandle(interface, filter));
    if (!sniff_handle) {
        std::cerr << "Failed to create pcap handle for interface: " << interface << "\n";
        throw std::runtime_error("Failed to create pcap handle.");
    }
    link_header_length = get_link_header_len(sniff_handle.get());
}

int CaptureSession::getLinkHeaderLength() const {
    return link_header_length;
}

void CaptureSession::startCapture(int packet_count) {
    if (!sniff_handle) {
        std::cerr << "Error: No valid capture handle for " << interface_name << ".\n";
        return;
    }

    stop_flag = false;

    auto callback = [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
        auto* session = reinterpret_cast<CaptureSession*>(user);
        session->packet_handler.handle(hdr, pkt, session->link_header_length);
    };

    int result = pcap_loop(
        sniff_handle.get(), packet_count,
        callback,
        reinterpret_cast<u_char*>(this) // Pass CaptureSession instance
    );

    if (result == PCAP_ERROR && !stop_flag) {
        std::cerr << "Error in pcap_loop (" << interface_name << "): "
                  << pcap_geterr(sniff_handle.get()) << "\n";
    }
}
void CaptureSession::stopCapture() {
    stop_flag = true;
    if (sniff_handle) {
        pcap_breakloop(sniff_handle.get());
    }
}

pcap_t* CaptureSession::createPcapHandle(const std::string& device, const std::string& filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;
    bpf_u_int32 netmask, srcip;

    if (pcap_lookupnet(device.c_str(), &srcip, &netmask, errbuf) == PCAP_ERROR) {
        std::cerr << "pcap_lookupnet: " << errbuf << std::endl;
        return nullptr;
    }

    pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live(): " << errbuf << std::endl;
        return nullptr;
    }

    if (!filter.empty()) {
        if (pcap_compile(handle, &bpf, filter.c_str(), 1, netmask) == PCAP_ERROR) {
            std::cerr << "pcap_compile(): " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            return nullptr;
        }

        if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
            std::cerr << "pcap_setfilter(): " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&bpf);
            pcap_close(handle);
            return nullptr;
        }

        pcap_freecode(&bpf);
    }

    // Only capture inbound packets (received packets)
    if (pcap_setdirection(handle, PCAP_D_IN) == PCAP_ERROR) {
        std::cerr << "pcap_setdirection(): " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return nullptr;
    }

    return handle;
}

bool CaptureSession::getStats(struct pcap_stat& stats) const {
    if (sniff_handle && pcap_stats(sniff_handle.get(), &stats) >= 0) {
        return true;
    }
    return false;
}

const std::string& CaptureSession::getInterfaceName() const {
    return interface_name;
}

PacketHandler& CaptureSession::getPacketHandler() {
    return packet_handler;
}
