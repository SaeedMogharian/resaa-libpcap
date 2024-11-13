#ifndef PCAP_UTILS_H
#define PCAP_UTILS_H

#include <memory>
#include <pcap/pcap.h>

/**
 * Creates a smart pointer wrapper for a raw pcap_t handle.
 * @param raw_handle The raw pcap_t handle to wrap.
 * @return A unique_ptr managing the lifecycle of the handle.
 */
std::unique_ptr<pcap_t, decltype(&pcap_close)> createPcapHandleWrapper(pcap_t* raw_handle);

/**
 * Determines the link-layer header length for the given pcap handle.
 * @param handle The pcap handle.
 * @return The header length, or 0 on failure.
 */
int get_link_header_len(pcap_t* handle);

#endif // PCAP_UTILS_H
