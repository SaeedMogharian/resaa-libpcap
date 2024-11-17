//
// Created by Resaa on 11/14/2024.
//
#include <iostream>
#include <string>
#include <unordered_map>
#include <csignal>
#include <functional>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <iomanip>
#include <utility>
#include <functional>
#include <thread>
#include <vector>

using namespace std;


class LibPcapWrapper {
    public:
        using pcapConn = pcap_t;
        static pcapConn* openLiveConnection(const string& interface_name, const string& filter) {
            char errbuf[PCAP_ERRBUF_SIZE];
            struct bpf_program bpf;
            bpf_u_int32 netmask, srcip;

            if (pcap_lookupnet(interface_name.c_str(), &srcip, &netmask, errbuf) == PCAP_ERROR) {
                cerr << "pcap_lookupnet: " << errbuf << endl;
                return nullptr;
            }

            pcap_t* conn = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, errbuf);
            if (!conn) {
                cerr << "pcap_open_live(): " << errbuf << endl;
                return nullptr;
            }

            if (!filter.empty()) {
            if (pcap_compile(conn, &bpf, filter.c_str(), 1, netmask) == PCAP_ERROR) {
                cerr << "pcap_compile(): " << pcap_geterr(conn) << endl;
                pcap_close(conn);
                return nullptr;
            }
            pcap_freecode(&bpf);


            if (pcap_setfilter(conn, &bpf) == PCAP_ERROR) {
                cerr << "pcap_setfilter(): " << pcap_geterr(conn) << endl;
                return nullptr;
            }
            }

            // Only capture inbound packets (received packets)
            if (pcap_setdirection(conn, PCAP_D_IN) == PCAP_ERROR) {
                cerr << "pcap_setdirection(): " << pcap_geterr(conn) << endl;
                return nullptr;
            }
            return conn;
        }
        // PCAP_API int	pcap_loop(pcap_t *, int, pcap_handler, u_char *);
        static void startPacketCapture(const function<void()> &packetManager, pcapConn* conn, int packet_count = 0) {
            if (!conn) {
                cerr << "Error: No valid capture handle" << endl;
                return;
            }

            // Start the packet capture with a set count or continually if the count is 0.
            int result = pcap_loop(conn, packet_count, packetManager, reinterpret_cast<u_char*>(nullptr));
            if (result == PCAP_ERROR) {
                cerr << "Error in pcap_loop (" << interface_name << "): "
                    << pcap_geterr(conn) << endl;
            }
        }
        static void packetInjection(const pcapConn* to, const struct pcap_pkthdr* packet_header, const u_char* packet_pointer) {
            int result = pcap_inject(to, packet_pointer, packet_header->len);
            if (result == PCAP_ERROR) {
                cerr << "Failed to inject packet: "
                          << pcap_geterr(injection_handle.get()) << endl;
            }
        }

        static u_char* packetCapture(pcapConn* conn){
            struct pcap_pkthdr* header;
            const u_char* packet = pcap_next(handle, header);
            if (packet) {
                cout << "Captured a packet with length:"<< header.len <<" bytes"<< endl;
                return header.len;
            } else {
                cout << "Packet capture failed" << endl;
                return -1;
            }

        }
           // const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
           // int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);

        static pair<string, string> stopPacketCapture(pcapConn conn) {
              pcap_breakloop(conn);
              pair<string, string> stats_report;
              struct pcap_stat stats;
              if (pcap_stats(conn, &stats) >= 0) {
                  stats_report = make_pair(static_cast<string>(stats.ps_recv), static_cast<string>(stats.ps_drop));
              }
              pcap_close(conn);
              return stats_report;
        }
        static int getLinkHeaderLen(pcapConn* conn) {
            int linkhdrlen = 0;
            int linktype = pcap_datalink(conn);
            if (linktype == PCAP_ERROR) {
                std::cerr << "pcap_datalink(): " << pcap_geterr(conn) << std::endl;
                return -1;
            }

            switch (linktype) {
                case DLT_NULL: linkhdrlen = 4; break;
                case DLT_EN10MB: linkhdrlen = 14; break;
                case DLT_SLIP:
                case DLT_PPP: linkhdrlen = 24; break;
                default: linkhdrlen = 0;
            }

            return linkhdrlen;
        }
};


class Interface {
    private:
        string name;
        unordered_map<string, pair<int, int>> ip_stats; // ip: (packet, byte)
        // ip_stats["192.168.0.1"] = make_pair(10, 100); // (packet, byte)
        int link_header_len = 0;


    public:

        explicit Interface(string nic_name) : name(move(nic_name)) {}

        void printIpStats() const {
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
        void updateIpStats(const string& ip, int packets_size) {
            if (ip_stats.find(ip) != ip_stats.end()) {
                ip_stats[ip].first++; // Increment packets
                ip_stats[ip].second += packets_size;  // Increment bytes
            } else {
                ip_stats[ip] = make_pair(1, packets_size); // Initialize if not present
            }
        }

        int getPacketsCount() const {
            int totalPackets = 0;
            for (const auto& entry : ip_stats) {
                totalPackets += entry.second.first; // Sum up the packet counts
            }
            return totalPackets;
        }

        // get IP from packet pointer
        string getIpFromPacket(const u_char* packet) const {
            auto* ip_header = reinterpret_cast<const struct ip*>(packet + link_header_len);
            string src_ip = inet_ntoa(ip_header->ip_src);
            return src_ip;
        }

        string getName() const {
            return name;
        }
        void setLinkHeaderLen(const int len) {
            link_header_len = len;
        }
};


class Connection {
    private:
        Interface* primary;
        Interface* secondary;
        string filter;

        int injection_failures = 0;

        void sniffer(u_char *user, const struct pcap_pkthdr* packet_header, const u_char* packet_pointer) {
            const string ip = primary.getIpFromPacket(packet_pointer);
            primary.updateIpStats(ip, packet_header->len);
            // packet_pointer, packet_header->len, primary.getName());
        }

        void injector(u_char *user, const struct pcap_pkthdr* packet_header, const u_char* packet_pointer, Interface inj_int = Interface("")) {
            sniffer(user, packet_header, packet_pointer);
            LibPcapWrapper::pcapConn* conn = LibPcapWrapper::openLiveConnection(inj_int, "");
            LibPcapWrapper::packetInjection(conn, packet_header, packet_pointer);
        }

    public:
        explicit Connection(Interface primary_nic, Interface secondary_nic, string conn_filter)
            : primary(move(primary_nic)), secondary(move(secondary_nic)), filter(move(conn_filter)) {}

        static void stopSniff(LibPcapWrapper::pcapConn* conn, const Interface* interface) {
            string recv, drop;
            recv, drop = LibPcapWrapper::stopPacketCapture(conn);
            cout << endl << "On Interface " << interface->getName() << endl
                << interface->getPacketsCount() << " packets processed" << endl
                << recv << " packets received by filter" << endl
                << drop << " packets dropped" << endl << endl;

            interface->printIpStats();
            pcap_close(conn);
        }

        static void stopInject(const Interface* prim, const Interface* secon) {
            int all = prim->getPacketsCount()+secon->getPacketCount();
            cout << left
                  << setw(22) << prim->getName() << "::" << secon->getName()
                  << setw(17) << all
                  << setw(10) << injection_failures
                  << (all > 0
                      ? (100.0 * (all - injection_failures) / all)
                      : 0.0)
                  << endl;
        }

        void monitoring() {
            LibPcapWrapper::pcapConn* sniff = LibPcapWrapper::openLiveConnection(primary, filter);
            primary.setLinkHeaderLen(LibPcapWrapper::getLinkHeaderLen(sniff));
            LibPcapWrapper::startPacketCapture(sniffer, sniff);
            stopSniff(sniff);
            exit(0);
        }


        void bridge() {
            LibPcapWrapper::pcapConn* primary_sniff = LibPcapWrapper::openLiveConnection(primary, filter);
            LibPcapWrapper::pcapConn* secondary_sniff = LibPcapWrapper::openLiveConnection(secondary, filter);
            secondary.setLinkHeaderLen(LibPcapWrapper::getLinkHeaderLen(secondary_sniff));
            primary.setLinkHeaderLen(LibPcapWrapper::getLinkHeaderLen(primary_sniff));


            std::vector<std::thread> threads;

            // Start packet capture for primary connection
            threads.emplace_back([primary_sniff, secondary]() {
                LibPcapWrapper::startPacketCapture(injector, primary_sniff, secondary);
            });

            // Start packet capture for secondary connection
            threads.emplace_back([secondary_sniff, primary]() {
                LibPcapWrapper::startPacketCapture(injector, secondary_sniff, primary);
            });

            // Wait for both threads to complete
            for (auto& t : threads) {
                if (t.joinable()) {
                    t.join();
                }
            }

            // Stop sniffing on both connections
            stopSniff(primary_sniff, primary);
            stopSniff(secondary_sniff, secondary);
            stopInject(primary, secondary)

            exit(0);
        }
    }
};

int main(int argc, char* argv[]) {
  // Application app;
  // global_app = &app; // Set the global application pointer for signal handling

  // Set up signal handlers
  signal(SIGINT, [](int signo) { if (global_app) global_app->stop(); });
  signal(SIGTERM, [](int signo) { if (global_app) global_app->stop(); });
  signal(SIGQUIT, [](int signo) { if (global_app) global_app->stop(); });
  //
  // app.run(argc, argv);
  return 0;
}

