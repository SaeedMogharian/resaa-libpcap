#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "PcapLiveDevice.h"
#include "SystemUtils.h"
#include "IPv4Layer.h"
#include <utility>
#include <csignal>


using namespace std;

using namespace pcpp;


class Stats{
    private:
        unordered_map<string, pair<int, int>> ip_stats;
        int injection_failure = 0;
    public:

         void printIpStats(string name) const {
            cout << "\nIP Statistics On Interface: " << name << endl;

            cout << left << setw(17) << "IP"
                 << setw(15) << "Packets Sent"
                 << setw(12) << "Bytes Sent" << endl;

            for (const auto& entry : ip_stats) {
                cout << left
                     << setw(17) << entry.first
                     << setw(15) << entry.second.first
                     << setw(12) << entry.second.second << endl;
            }

            if (ip_stats.empty()){
                cout << left
                     << setw(17) << "-"
                     << setw(15) << "-"
                     << setw(12) << "-" << endl;
            }
        }
        // Update both packet and byte counts for a specific IP address
        /**
         * Collect stats from a packet
         * only IPv4 packets are considered.
         */
        void consumePacket(Packet& packet)
        {
            // string ip = static_cast<string>(ipAdd);
            int packets_size = 0;
            // first let's go over the layers one by one and find out its type, its total length, its header length and its payload length
            for (auto* curLayer = packet.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
            {
                packets_size += curLayer->getDataLen();
            }

            // update
            IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
            if (ipv4Layer == nullptr) {
                // cerr << "Packet does not contain an IPv4 layer." << endl;
                return;
            }
            string ip = ipv4Layer->getSrcIPAddress().toString();

            if (ip_stats.find(ip) != ip_stats.end()) {
                ip_stats[ip].first++; // Increment packets
                ip_stats[ip].second += packets_size;  // Increment bytes
            } else {
                ip_stats[ip] = make_pair(1, packets_size); // Initialize if not present
            }
        }
        
        void clearIpStats(){
            ip_stats.clear();
        }
        int getPacketsCount() const {
            int totalPackets = 0;
            for (const auto& entry : ip_stats) {
                totalPackets += entry.second.first; // Sum up the packet counts
            }
            return totalPackets;
        }

        void increaseInjectionFailure(){
            injection_failure++;
        }

        void printInjectionFailure(string name){
            int pckt_cnt = getPacketsCount();
            cout << left
              << setw(22) << name
              << setw(21) << pckt_cnt
              << setw(10) << injection_failure
              << (pckt_cnt > 0
                  ? (100.0 * (pckt_cnt - injection_failure) / pckt_cnt)
                  : 0.0)
              << endl;
        }
};

struct injectionCookie {
    PcapLiveDevice* dev;
    Stats* stats;

    // Constructor to initialize the struct
    injectionCookie(PcapLiveDevice* device, Stats* statistics)
        : dev(device), stats(statistics) {}
};

// callback function for injection handling
static void injection(RawPacket* packet, PcapLiveDevice* nic_prim, void* data) {
    // Extract the stats object from the cookie
    struct injectionCookie* parsed_data = static_cast<struct injectionCookie*>(data); 
    PcapLiveDevice* dst_dev = parsed_data->dev;
    Stats* stats = parsed_data->stats;

    // Parse the raw packet
    Packet parsedPacket(packet);

    // Collect stats from packet
    stats->consumePacket(parsedPacket);

    bool success = dst_dev->sendPacket(*packet);
    if (!success) {
        cout << "Injection Failed on " << dst_dev->getName() << endl;
        stats->increaseInjectionFailure();
    }
}

void getDevInfo(PcapLiveDevice* conn){
    if (conn == nullptr)
    {
        cerr << "Cannot find interface with name of '" << conn->getName() << "'" << endl;
        exit(1);
    }

    // Get device info
    // ~~~~~~~~~~~~~~~

    // before capturing packets let's print some info about this interface
    cout << "Interface info:" << endl
            << "   Interface name:        " << conn->getName() << endl            // get interface name
            << "   Interface description: " << conn->getDesc() << endl            // get interface description
            << "   MAC address:           " << conn->getMacAddress() << endl      // get interface MAC address
            << "   Default gateway:       " << conn->getDefaultGateway() << endl  // get default gateway
            << "   Interface MTU:         " << conn->getMtu() << endl;            // get interface MTU

    if (!conn->getDnsServers().empty())
    {
        cout << "   DNS server:            " << conn->getDnsServers().front() << endl;
    }

    // open the device before start capturing/sending packets
    if (!conn->open())
    {
        cerr << "Cannot open device" << endl;
        exit(1);
    }
    

};


bool keepRunning = true;
void signalHandler(int signum) {
    cout << "  Stopping..." << endl;
    keepRunning = false;
}


/**
 * main method of the application
 */
int main(int argc, char* argv[])
{

    signal(SIGINT, signalHandler);

    string interface_prim = "";
    string interface_secn = "";
    string filter = "";

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

    // PcapLiveDevice 
	auto* primary = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_prim);	
    auto* secondary = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_secn);
    
    getDevInfo(primary);
    getDevInfo(secondary);
    
    filter += "inbound";

	// set the filter on the device
	if (!primary->setFilter(filter)) {
        cerr << "Failed to set filter on interface" << endl;
        return;
    }
    if (!secondary->setFilter(filter)) {
        cerr << "Failed to set filter on interface" << endl;
        return;
    }


    // Stats
    Stats prim_stats;
    Stats secn_stats;

	// Async packet capture with a callback function
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	cout << endl << "Starting async capture. Press ^C to stop..." << endl;
	// start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats
	// object as the cookie	
    auto* pi = new injectionCookie(secondary, &prim_stats);
    auto* si = new injectionCookie(primary, &secn_stats);
    primary->startCapture(injection, pi);
    secondary->startCapture(injection, si);
	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	while (keepRunning) {
        multiPlatformSleep(1);
    }
	// stop capturing packets
	primary->stopCapture();
    secondary->stopCapture();
    primary->close();
    secondary->close();

    // stop caturing packets
	prim_stats.printIpStats(primary->getName());
    secn_stats.printIpStats(secondary->getName());

    cout << endl << "Injection Statistics Report:" << endl;
    cout << left
        << setw(22) << "ReceivedOnInterface"
        << setw(21) << "PacketsInjectedFrom"
        << setw(10) << "Failures"
        << "SuccessRate (%)" << endl;
    prim_stats.printInjectionFailure(primary->getName());
    secn_stats.printInjectionFailure(secondary->getName());


	// clearIpStats stats
	prim_stats.clearIpStats();
    secn_stats.clearIpStats();


}
