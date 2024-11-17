#include <iostream>
#include <algorithm>
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"


using namespace std;

using namespace pcpp;


/**
 * A struct for collecting packet statistics
 */
struct PacketStats
{
	int ethPacketCount = 0;
	int ipv4PacketCount = 0;
	int ipv6PacketCount = 0;
	int tcpPacketCount = 0;
	int udpPacketCount = 0;
	int dnsPacketCount = 0;
	int httpPacketCount = 0;
	int sslPacketCount = 0;

	/**
	 * Clear all stats
	 */
	void clear()
	{
		ethPacketCount = ipv4PacketCount = ipv6PacketCount = tcpPacketCount = udpPacketCount = dnsPacketCount =
		    httpPacketCount = sslPacketCount = 0;
	}

	// Constructor is optional here since the members are already initialized
	PacketStats() = default;

	/**
	 * Collect stats from a packet
	 */
	void consumePacket(Packet& packet)
	{
		if (packet.isPacketOfType(Ethernet))
			ethPacketCount++;
		if (packet.isPacketOfType(IPv4))
			ipv4PacketCount++;
		if (packet.isPacketOfType(IPv6))
			ipv6PacketCount++;
		if (packet.isPacketOfType(TCP))
			tcpPacketCount++;
		if (packet.isPacketOfType(UDP))
			udpPacketCount++;
		if (packet.isPacketOfType(DNS))
			dnsPacketCount++;
		if (packet.isPacketOfType(HTTP))
			httpPacketCount++;
		if (packet.isPacketOfType(SSL))
			sslPacketCount++;
	}

	/**
	 * Print stats to console
	 */
	void printToConsole()
	{
		cout << "Ethernet packet count: " << ethPacketCount << endl
		          << "IPv4 packet count:     " << ipv4PacketCount << endl
		          << "IPv6 packet count:     " << ipv6PacketCount << endl
		          << "TCP packet count:      " << tcpPacketCount << endl
		          << "UDP packet count:      " << udpPacketCount << endl
		          << "DNS packet count:      " << dnsPacketCount << endl
		          << "HTTP packet count:     " << httpPacketCount << endl
		          << "SSL packet count:      " << sslPacketCount << endl;
	}
};

/**
 * A callback function for the async capture which is called each time a packet is captured
 */
static void onPacketArrives(RawPacket* packet, PcapLiveDevice* nic_prim, void* cookie)
{
	// extract the stats object form the cookie
	auto* stats = static_cast<PacketStats*>(cookie);

	// parsed the raw packet
	Packet parsedPacket(packet);

	// collect stats from packet
	stats->consumePacket(parsedPacket);
}

/**
 * a callback function for the blocking mode capture which is called each time a packet is captured
 */
static bool onPacketArrivesBlockingMode(RawPacket* packet, PcapLiveDevice* nic_prim, void* cookie)
{
	// extract the stats object from the cookie
	auto* stats = static_cast<PacketStats*>(cookie);

	// parsed the raw packet
	Packet parsedPacket(packet);

	// collect stats from packet
	stats->consumePacket(parsedPacket);

	// return false means we don't want to stop capturing after this callback
	return false;
}

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	// IPv4 address of the interface we want to sniff
	// string interfaceIPAddr = "10.0.0.1";
    string interfaceName = "ens160";


	// find the interface by IP address
    // PcapLiveDevice 
	auto* nic_prim = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceName);
    // getPcapLiveDeviceByIp(interfaceIPAddr);
	if (nic_prim == nullptr)
	{
		cerr << "Cannot find interface with IPv4 address of '" << interfaceName << "'" << endl;
		return 1;
	}

	// Get device info
	// ~~~~~~~~~~~~~~~

	// before capturing packets let's print some info about this interface
	cout << "Interface info:" << endl
	          << "   Interface name:        " << nic_prim->getName() << endl            // get interface name
	          << "   Interface description: " << nic_prim->getDesc() << endl            // get interface description
	          << "   MAC address:           " << nic_prim->getMacAddress() << endl      // get interface MAC address
	          << "   Default gateway:       " << nic_prim->getDefaultGateway() << endl  // get default gateway
	          << "   Interface MTU:         " << nic_prim->getMtu() << endl;            // get interface MTU

	if (!nic_prim->getDnsServers().empty())
	{
		cout << "   DNS server:            " << nic_prim->getDnsServers().front() << endl;
	}

	// open the device before start capturing/sending packets
	if (!nic_prim->open())
	{
		cerr << "Cannot open device" << endl;
		return 1;
	}

	// create the stats object
	PacketStats stats;

	// Async packet capture with a callback function
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	cout << endl << "Starting async capture..." << endl;

	// start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats
	// object as the cookie
	nic_prim->startCapture(onPacketArrives, &stats);

	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	multiPlatformSleep(10);

	// stop capturing packets
	nic_prim->stopCapture();

	// print results
	cout << "Results:" << endl;
	stats.printToConsole();

	// clear stats
	stats.clear();

	// Capturing packets in a packet vector
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	cout << endl << "Starting capture with packet vector..." << endl;

	// create an empty packet vector object
	RawPacketVector packetVec;

	// start capturing packets. All packets will be added to the packet vector
	nic_prim->startCapture(packetVec);

	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	multiPlatformSleep(10);

	// stop capturing packets
	nic_prim->stopCapture();

	// go over the packet vector and feed all packets to the stats object
	for (const auto& packet : packetVec)
	{
		Packet parsedPacket(packet);
		stats.consumePacket(parsedPacket);
	}

	// print results
	cout << "Results:" << endl;
	stats.printToConsole();

	// clear stats
	stats.clear();

	// Capturing packets in blocking mode
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	cout << endl << "Starting capture in blocking mode..." << endl;

	// start capturing in blocking mode. Give a callback function to call to whenever a packet is captured, the stats
	// object as the cookie and a 10 seconds timeout
	nic_prim->startCaptureBlockingMode(onPacketArrivesBlockingMode, &stats, 10);

	// thread is blocked until capture is finished

	// capture is finished, print results
	cout << "Results:" << endl;
	stats.printToConsole();

	stats.clear();

	// Sending single packets
	// ~~~~~~~~~~~~~~~~~~~~~~

	cout << endl << "Sending " << packetVec.size() << " packets one by one..." << endl;

	// go over the vector of packets and send them one by one
	bool allSent = all_of(packetVec.begin(), packetVec.end(),
	                           [nic_prim](RawPacket* packet) { return nic_prim->sendPacket(*packet); });

	if (!allSent)
	{
		cerr << "Couldn't send packet" << endl;
		return 1;
	}

	cout << packetVec.size() << " packets sent" << endl;

	// Sending batch of packets
	// ~~~~~~~~~~~~~~~~~~~~~~~~

	cout << endl << "Sending " << packetVec.size() << " packets..." << endl;

	// send all packets in the vector. The returned number shows how many packets were actually sent (expected to be
	// equal to vector size)
	int packetsSent = nic_prim->sendPackets(packetVec);

	cout << packetsSent << " packets sent" << endl;

	// Using filters
	// ~~~~~~~~~~~~~

	// create a filter instance to capture only traffic on port 80
	PortFilter portFilter(80, SRC_OR_DST);

	// create a filter instance to capture only TCP traffic
	ProtoFilter protocolFilter(TCP);

	// create an AND filter to combine both filters - capture only TCP traffic on port 80
	AndFilter andFilter;
	andFilter.addFilter(&portFilter);
	andFilter.addFilter(&protocolFilter);

	// set the filter on the device
	nic_prim->setFilter(andFilter);

	cout << endl << "Starting packet capture with a filter in place..." << endl;

	// start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats
	// object as the cookie
	nic_prim->startCapture(onPacketArrives, &stats);

	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	multiPlatformSleep(10);

	// stop capturing packets
	nic_prim->stopCapture();

	// print results - should capture only packets which match the filter (which is TCP port 80)
	cout << "Results:" << endl;
	stats.printToConsole();

	// close the device before application ends
	nic_prim->close();
}
