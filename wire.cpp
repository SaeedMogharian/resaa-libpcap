#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <mutex> // For thread safety
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "PcapLiveDevice.h"
#include "SystemUtils.h"
#include "IPv4Layer.h"
#include <utility>
#include <csignal>

using namespace std;
using namespace pcpp;

std::mutex statsMutex; // Protects console output and shared resources

class Stats {
private:
    unordered_map<string, pair<int, int>> ip_stats;
    int injection_failure = 0;

public:
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
            cout << left
                 << setw(17) << "-"
                 << setw(15) << "-"
                 << setw(12) << "-" << endl;
        }
    }

    void consumePacket(Packet &packet) {
        int packets_size = 0;
        for (auto *curLayer = packet.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer()) {
            packets_size += curLayer->getDataLen();
        }

        IPv4Layer *ipv4Layer = packet.getLayerOfType<IPv4Layer>();
        if (ipv4Layer == nullptr) {
            return;
        }
        string ip = ipv4Layer->getSrcIPAddress().toString();

        if (ip_stats.find(ip) != ip_stats.end()) {
            ip_stats[ip].first++;              // Increment packets
            ip_stats[ip].second += packets_size; // Increment bytes
        } else {
            ip_stats[ip] = make_pair(1, packets_size); // Initialize if not present
        }
    }

    void clearIpStats() {
        ip_stats.clear();
    }

    int getPacketsCount() const {
        int totalPackets = 0;
        for (const auto &entry : ip_stats) {
            totalPackets += entry.second.first;
        }
        return totalPackets;
    }

    void increaseInjectionFailure() {
        injection_failure++;
    }

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

static void injection(RawPacket *packet, PcapLiveDevice *nic_prim, void *data) {
    auto *parsed_data = static_cast<pair<PcapLiveDevice *, Stats *> *>(data); // Use std::pair
    PcapLiveDevice *dst_dev = parsed_data->first;
    Stats *stats = parsed_data->second;

    Packet parsedPacket(packet);
    stats->consumePacket(parsedPacket);

    bool success = dst_dev->sendPacket(*packet);
    if (!success) {
        std::lock_guard<std::mutex> lock(statsMutex); // Protect the output
        cout << "Injection Failed on " << dst_dev->getName() << endl;
        stats->increaseInjectionFailure();
    }
}

bool keepRunning = true;
void signalHandler(int signum) {
    cout << "  Stopping..." << endl;
    keepRunning = false;
}

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
    signal(SIGINT, signalHandler);

    string interface_prim = "";
    string interface_secn = "";
    string filter = "inbound ";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-i" && i + 1 < argc) {
            interface_prim = argv[++i];
        } else if (arg == "-j" && i + 1 < argc) {
            interface_secn = argv[++i];
        } else if (arg == "-h") {
            cout << "Usage: " << argv[0]
                 << " [-h] [-i primary_interface] [-j secondary_interface] [BPF filter]" << endl;
            exit(0);
        } else if (!arg.empty() && arg[0] == '-') {
            cerr << "Unknown option: " << arg << endl;
            exit(1);
        } else {
            filter += arg + " ";
        }
    }
    if (interface_secn.empty() || interface_prim.empty()) {
        cerr << "Interface not specified!" << endl;
        return 1;
    }

    auto *primary = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_prim);
    auto *secondary = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_secn);

    
    checkDev(primary);
    checkDev(secondary);

    if (!primary->setFilter(filter) || !secondary->setFilter(filter)) {
        cerr << "Failed to set filter on interface" << endl;
        return 1;
    }

    Stats prim_stats, secn_stats;
    // Replace injectionCookie with std::pair
    auto pi = new pair<PcapLiveDevice *, Stats *>(secondary, &prim_stats);
    auto si = new pair<PcapLiveDevice *, Stats *>(primary, &secn_stats);

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

    primary->stopCapture();
    secondary->stopCapture();
    primary->close();
    secondary->close();

    prim_stats.clearIpStats();
    secn_stats.clearIpStats();
}
