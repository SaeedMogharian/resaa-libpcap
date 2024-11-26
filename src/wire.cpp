#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <mutex>
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "PcapLiveDevice.h"
#include "SystemUtils.h"
#include "IPv4Layer.h"
#include <utility>
#include <csignal>
#include <unordered_map>  

using namespace std;
using namespace pcpp;

// Mutex for synchronizing access to shared resources
std::mutex statsMutex;

// Class to manage statistics about IP traffic
class Stats {
private:
    unordered_map<string, pair<int, int>> ip_stats; // Map to store IP statistics: {IP -> (packet count, byte count)}
    int injection_failure = 0;                     // Counter for packet injection failures

public:
    // Print IP statistics for a specific network interface
    void printIpStats(string name) const {
        cout << "\nIP Statistics On Interface: " << name << endl;

        cout << left << setw(17) << "IP"
             << setw(15) << "Packets Sent"
             << setw(12) << "Bytes Sent" << endl;

        for (const auto &entry : ip_stats) {
            cout << left
                 << setw(17) << entry.first
                 << setw(15) << entry.second.first
                 << setw(12) << entry.second.second << endl;
        }

        if (ip_stats.empty()) {
            // Print a placeholder if no stats are available
            cout << left
                 << setw(17) << "-"
                 << setw(15) << "-"
                 << setw(12) << "-" << endl;
        }
    }

    // Update IP statistics based on the given packet
    void consumePacket(Packet &packet) {
        int packets_size = 0;
        
        // Calculate total packet size by iterating over all layers
        for (auto *curLayer = packet.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer()) {
            packets_size += curLayer->getDataLen();
        }

        IPv4Layer *ipv4Layer = packet.getLayerOfType<IPv4Layer>(); // Extract IPv4 layer

        if (ipv4Layer == nullptr) {
            return;
        }
        string ip = ipv4Layer->getSrcIPAddress().toString();  // Get source IP address

        if (ip_stats.find(ip) != ip_stats.end()) {
            ip_stats[ip].first++;              // Increment packets
            ip_stats[ip].second += packets_size; // Increment bytes
        } else {
            ip_stats[ip] = make_pair(1, packets_size); // Initialize if not present
        }
    }

    // Clear all stored IP statistics
    void clearIpStats() {
        ip_stats.clear();
    }

    // Get total packet count
    int getPacketsCount() const {
        int totalPackets = 0;
        for (const auto &entry : ip_stats) {
            totalPackets += entry.second.first;
        }
        return totalPackets;
    }

    // Increment the injection failure counter
    void increaseInjectionFailure() {
        injection_failure++;
    }

    // Print packet injection failure statistics
    void printInjectionFailure(string name) const {
        int pckt_cnt = getPacketsCount();
        cout << left
             << setw(22) << name
             << setw(21) << pckt_cnt
             << setw(10) << injection_failure
             << (pckt_cnt > 0 ? (100.0 * (pckt_cnt - injection_failure) / pckt_cnt) : 0.0)
             << endl;
    }
};

    // Packet injection callback function
static void injection(RawPacket *packet, PcapLiveDevice *nic_prim, void *data) {
    auto *parsed_data = static_cast<pair<PcapLiveDevice *, Stats *> *>(data); // Parse input data
    PcapLiveDevice *dst_dev = parsed_data->first;                            // Destination device
    Stats *stats = parsed_data->second;                                      // Stats object

    Packet parsedPacket(packet);                  // Parse raw packet into Packet object
    stats->consumePacket(parsedPacket); // Update stats with packet info

    bool success = dst_dev->sendPacket(*packet);
    if (!success) {
        std::lock_guard<std::mutex> lock(statsMutex); // Protect output from concurrent access
        cout << "Injection Failed on " << dst_dev->getName() << endl;
        stats->increaseInjectionFailure(); // Update failure count
    }
}

// Flag to control the program's main loop
bool keepRunning = true;

// Signal handler to handle interrupt signal (e.g., Ctrl+C)
void signalHandler(int signum) {
    cout << "  Stopping..." << endl;
    keepRunning = false;
}

// Check if a device is valid and can be opened
void checkDev(PcapLiveDevice* dev){
    if (dev == nullptr) {
        cerr << "Cannot find interface with name of '" << dev->getName() << "'" << endl;
        exit(1);
    }
    if (!dev->open()) {
        cerr << "Cannot open device" << dev->getName() << endl;
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    ssignal(SIGINT, signalHandler); // Register signal handler

    string interface_prim = "";  // Primary interface name
    string interface_secn = "";  // Secondary interface name
    string filter = "inbound "; // Default BPF filter
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-i" && i + 1 < argc) {
            interface_prim = argv[++i]; // Get primary interface
        } else if (arg == "-j" && i + 1 < argc) {
            interface_secn = argv[++i]; // Get secondary interface
        } else if (arg == "-h") {
            cout << "Usage: " << argv[0]
                 << " [-h] [-i primary_interface] [-j secondary_interface] [BPF filter]" << endl;
            exit(0);
        } else if (!arg.empty() && arg[0] == '-') {
            cerr << "Unknown option: " << arg << endl;
            exit(1);
        } else {
            filter += arg + " "; // Add additional filter arguments
        }
    }
    if (interface_secn.empty() || interface_prim.empty()) {
        cerr << "Interface not specified!" << endl;
        return 1;
    }

    auto *primary = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_prim);
    auto *secondary = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_secn);

    
    checkDev(primary); // Validate primary interface
    checkDev(secondary); // Validate secondary interface

    if (!primary->setFilter(filter) || !secondary->setFilter(filter)) {
        cerr << "Failed to set filter on interface" << endl;
        return 1;
    }

    Stats prim_stats, secn_stats; // Stats object for the interfaces

    auto *pi = new pair<PcapLiveDevice *, Stats *>(secondary, &prim_stats);
    auto *si = new pair<PcapLiveDevice *, Stats *>(primary, &secn_stats);

    primary->startCapture(injection, pi);
    secondary->startCapture(injection, si);

    
    while (keepRunning) {
        cout << endl << "Async capture&inject. Press ^C to stop..." << endl;

        multiPlatformSleep(1);
        {
            std::lock_guard<std::mutex> lock(statsMutex);
            system("clear"); // Clears the screen for updated live stats

            // Print IP stats for both interfaces
            cout << "Live Statistics Report:" << endl;
            prim_stats.printIpStats(primary->getName());
            secn_stats.printIpStats(secondary->getName());

            // Print Injection statistics
            cout << endl << "Injection Statistics:" << endl;
            cout << left
                 << setw(22) << "ReceivedOnInterface"
                 << setw(21) << "PacketsInjectedFrom"
                 << setw(10) << "Failures"
                 << "SuccessRate (%)" << endl;
            prim_stats.printInjectionFailure(primary->getName());
            secn_stats.printInjectionFailure(secondary->getName());
        }
    }

    // Stop capturing and clean up
    primary->stopCapture();
    secondary->stopCapture();
    primary->close();
    secondary->close();

    prim_stats.clearIpStats(); // Clear statistics
    secn_stats.clearIpStats();
}
