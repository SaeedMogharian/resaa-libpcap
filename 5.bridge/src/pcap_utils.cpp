#include "pcap_utils.h"
#include <iostream>

std::unique_ptr<pcap_t, decltype(&pcap_close)> createPcapHandleWrapper(pcap_t* raw_handle) {
    return std::unique_ptr<pcap_t, decltype(&pcap_close)>(raw_handle, &pcap_close);
}

int get_link_header_len(pcap_t* handle) {
    int linktype = pcap_datalink(handle);
    if (linktype == PCAP_ERROR) {
        std::cerr << "pcap_datalink(): " << pcap_geterr(handle) << std::endl;
        return 0;
    }

    switch (linktype) {
        case DLT_NULL: return 4;
        case DLT_EN10MB: return 14;
        case DLT_SLIP:
        case DLT_PPP: return 24;
        default: return 0;
    }
}
