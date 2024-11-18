#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"
#include "IPv4Layer.h"
#include <utility>


using namespace std;

using namespace pcpp;


class IpStats{
    private:
        unordered_map<string, pair<int, int>> ip_stats;
    public:

         void print(string name) const {
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
        }
        // Update both packet and byte counts for a specific IP address
    
        /**
         * Collect stats from a packet
         */
        void consumePacket(Packet& packet)
        {
            auto ipAdd = packet.getLayerOfType<IPv4Layer>()->getSrcIPAddress().getIPv4();
            // string ip = static_cast<string>(ipAdd);
            int packets_size = 0;
            // first let's go over the layers one by one and find out its type, its total length, its header length and its payload length
            for (auto* curLayer = packet.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
            {
                packets_size += curLayer->getDataLen();
            }

            // update
            // if (ip_stats.find(ip) != ip_stats.end()) {
            //     ip_stats[ip].first++; // Increment packets
            //     ip_stats[ip].second += packets_size;  // Increment bytes
            // } else {
            //     ip_stats[ip] = make_pair(1, packets_size); // Initialize if not present
            // }
        }
        
        void clear(){
            ip_stats.clear();
        }
        int getPacketsCount() const {
            int totalPackets = 0;
            for (const auto& entry : ip_stats) {
                totalPackets += entry.second.first; // Sum up the packet counts
            }
            return totalPackets;
        }

};


struct injectionCookie {PcapLiveDevice* dev; IpStats* stats;};

static void injection(RawPacket* packet, PcapLiveDevice* nic_prim, void* data){
// extract the stats object form the cookie
    struct injectionCookie * parsed_data = data; 
    PcapLiveDevice* dst_dev = parsed_data->dev;
    IpStats* stats = parsed_data->stats;

    // parsed the raw packet
    Packet parsedPacket(packet);

    // collect stats from packet
    stats->consumePacket(parsedPacket);

    bool success = dst_dev->sendPacket(*packet);
    if (!success){
        cout << "Injection Faild on " << dst_dev->getName() << endl ;
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



/**
 * main method of the application
 */


int main(int argc, char* argv[])
{
	// find the interface by IP address
    // PcapLiveDevice 
	auto* primary = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName("ens160");	
    auto* secondary = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName("ens192");	
	
    getDevInfo(primary);
    getDevInfo(secondary);

    // Using filters
    PortFilter portFilter(80, SRC_OR_DST);

	// create a filter instance to capture only TCP traffic
	ProtoFilter protocolFilter(TCP);

	// create an AND filter to combine both filters - capture only TCP traffic on port 80
	AndFilter andFilter;
	andFilter.addFilter(&portFilter);
	andFilter.addFilter(&protocolFilter);

	// set the filter on the device
	primary->setFilter(andFilter);
    secondary->setFilter(andFilter);


    // IpStats
    IpStats prim_stats;
    IpStats secn_stats;

	// Async packet capture with a callback function
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	cout << endl << "Starting async capture..." << endl;

	// start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats
	// object as the cookie
	primary->startCapture(injection, injectionCookie(&secondary, &prim_stats));
    secondary->startCapture(injection, injectionCookie(&primary, &secn_stats));

	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	multiPlatformSleep(10);

	// stop capturing packets
	primary->stopCapture();
    secondary->stopCapture();

    // stop capturing packets
	prim_stats.print();
    secn_stats.print();


	// clear stats
	prim_stats->clear();
    secn_stats->clear();


}
