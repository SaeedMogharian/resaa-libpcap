#include <iostream>
#include <string>
#include <unordered_map>
#include <csignal>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <memory>
#include <iomanip>
#include <thread>
#include <vector>

using namespace std;

unique_ptr<pcap_t, decltype(&pcap_close)> createPcapHandleWrapper(pcap_t* raw_handle) {
    return unique_ptr<pcap_t, decltype(&pcap_close)>(raw_handle, &pcap_close);
}


// Forward declarations
class PacketHandler;
class StatisticsManager;
class CaptureSession;

class IpStats {
public:
    // Attributes (member variables)
    int packets_sent = 0;
    int bytes_sent = 0;
    string interface;

    // Constructor to initialize attributes (optional)
    IpStats(int packet, int byte, const string& intr) : packets_sent(packet), bytes_sent(byte), interface(intr) {}

};


// Statistics Manager
class StatisticsManager {
private:
    unordered_map<string, IpStats> ip_statistics;

public:
    void update(const u_char* packet, int packet_size, const string& interface, int linkhdrlen) {

        linkhdrlen = 14;

        struct ip* iphdr = (struct ip*)(packet + linkhdrlen);

        char dstip[INET_ADDRSTRLEN];


        if (!inet_ntop(AF_INET, &iphdr->ip_src, dstip, INET_ADDRSTRLEN)) {
            cerr << "inet_ntop failed: " << strerror(errno) << endl;
            return;
        }


        auto& stats = ip_statistics[dstip];
        stats.packets_sent++;
        stats.bytes_sent += packet_size;
        stats.interface = interface;
    }

    void print() const {
        cout << "\nIP Address Statistics:\n";
        cout << left << setw(17) << "IP Address"
                  << setw(15) << "Packets Sent"
                  << setw(12) << "Bytes Sent"
                  << setw(12) << "Interface" << "\n";

        for (const auto& [ip, stats] : ip_statistics) {
            cout << left
                      << setw(17) << ip
                      << setw(15) << stats.packets_sent
                      << setw(12) << stats.bytes_sent
                      << setw(12) << stats.interface << "\n";
        }
    }
};

// Packet Handler
class PacketHandler {
private:
    unique_ptr<pcap_t, decltype(&pcap_close)> injection_handle;
    string interface_name;
    StatisticsManager& stats_manager;
    int injection_failures = 0;
    int packets_processed = 0;

public:
    int getPacketsProcessed() const {
            return packets_processed;
        }

    PacketHandler(unique_ptr<pcap_t, decltype(&pcap_close)> injectionHandle,
                  const string& interface,
                  StatisticsManager& stats,
                  int linkHeaderLen)
        : injection_handle(move(injectionHandle)),
          interface_name(interface),
          stats_manager(stats),
          linkhdrlen(linkHeaderLen) {}

    static void packetCallback(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
        auto* handler = reinterpret_cast<PacketHandler*>(user);
        handler->handle(hdr, pkt);
    }


    void handle(const struct pcap_pkthdr* packethdr, const u_char* packetptr) {
        packets_processed++;
        if (injection_handle && pcap_inject(injection_handle.get(), packetptr, packethdr->len) == PCAP_ERROR) {
            cerr << "Failed to inject packet from interface " << interface_name << ": "
                      << pcap_geterr(injection_handle.get()) << "\n";
            injection_failures++;
        }

        stats_manager.update(packetptr, packethdr->len, interface_name, linkhdrlen);
    }

    void printInjectionStatistics() const {
        cout << left
                  << setw(22) << interface_name
                  << setw(17) << packets_processed
                  << setw(10) << injection_failures
                  << fixed << setprecision(2)
                  << (packets_processed > 0
                      ? (100.0 * (packets_processed - injection_failures) / packets_processed)
                      : 0.0)
                  << "%\n";
    }
};




class CaptureSession {
private:
    string interface_name;
    unique_ptr<pcap_t, decltype(&pcap_close)> sniff_handle;
    PacketHandler packet_handler;
    int linkhdrlen;
    volatile bool stop_flag = false; // Stop flag for capture loop

public:
    void calculateLinkHeaderLength() {
        int linktype = pcap_datalink(sniff_handle.get());
        if (linktype == PCAP_ERROR) {
            cout << "in if" << endl;
            cerr << "pcap_datalink(): " << pcap_geterr(sniff_handle.get()) << endl;
            return;
        }

        cout << "########### linktype " << linktype << endl;

        switch (linktype) {
            case DLT_NULL: linkhdrlen = 4; break;
            case DLT_EN10MB: linkhdrlen = 14; break;
            case DLT_SLIP:
            case DLT_PPP: linkhdrlen = 24; break;
            default: linkhdrlen = 0;
        }
    }

    CaptureSession(const string& interface, const string& filter, PacketHandler handler)
        : interface_name(interface),
          sniff_handle(nullptr, pcap_close),
          packet_handler(move(handler)) {
        sniff_handle.reset(createPcapHandle(interface, filter));
        calculateLinkHeaderLength();
    }

    PacketHandler& getPacketHandler() {
        return packet_handler;
    }

    void startCapture(int packet_count = 0) {
        if (!sniff_handle) {
            cerr << "Error: No valid capture handle for " << interface_name << ".\n";
            return;
        }

        stop_flag = false; // Reset stop flag

        // Start packet capture loop
        int result = pcap_loop(
            sniff_handle.get(), packet_count,
            &PacketHandler::packetCallback, // Use the static callback
            reinterpret_cast<u_char*>(&packet_handler) // Pass PacketHandler instance
        );

        // Handle errors unless stopped intentionally
        if (result == PCAP_ERROR && !stop_flag) {
            cerr << "Error in pcap_loop (" << interface_name << "): "
                    << pcap_geterr(sniff_handle.get()) << "\n";
        }
    }


    void stopCapture() {
        stop_flag = true;
        if (sniff_handle) {
            pcap_breakloop(sniff_handle.get());
        }
    }

    static pcap_t* createPcapHandle(const string& device, const string& filter) {
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program bpf;
        bpf_u_int32 netmask, srcip;

        if (pcap_lookupnet(device.c_str(), &srcip, &netmask, errbuf) == PCAP_ERROR) {
            cerr << "pcap_lookupnet: " << errbuf << endl;
            return nullptr;
        }

        pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            cerr << "pcap_open_live(): " << errbuf << endl;
            return nullptr;
        }

        if (!filter.empty()) {
            if (pcap_compile(handle, &bpf, filter.c_str(), 1, netmask) == PCAP_ERROR) {
                cerr << "pcap_compile(): " << pcap_geterr(handle) << endl;
                pcap_close(handle);
                return nullptr;
            }
            pcap_freecode(&bpf);


            if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
                cerr << "pcap_setfilter(): " << pcap_geterr(handle) << endl;
                return nullptr;
            }
        }

        // Only capture inbound packets (received packets)
        if (pcap_setdirection(handle, PCAP_D_IN) == PCAP_ERROR) {
            cerr << "pcap_setdirection(): " << pcap_geterr(handle) << endl;
            return nullptr;
        }



        return handle;
    }

    bool getStats(struct pcap_stat& stats) const {
        if (sniff_handle && pcap_stats(sniff_handle.get(), &stats) >= 0) {
            return true;
        }
        return false;
    }

    const string& getInterfaceName() const {
        return interface_name;
    }

};


// Main Application
class Application {
private:
    string interface_prim;
    string interface_secn;
    string filter;
    int count = 0;
    StatisticsManager stats_manager;

    unique_ptr<CaptureSession> primary_session;
    unique_ptr<CaptureSession> secondary_session;

public:
    void run(int argc, char* argv[]) {
        parseArguments(argc, argv);

        if (interface_prim.empty()) {
            cerr << "At least one interface must be specified using -i.\n";
            return;
        }

        if (!interface_secn.empty()) {
            auto primaryInjector = createPcapHandleWrapper(
                CaptureSession::createPcapHandle(interface_secn, filter));
            auto secondaryInjector = createPcapHandleWrapper(
                CaptureSession::createPcapHandle(interface_prim, filter));

            primary_session = make_unique<CaptureSession>(
                interface_prim, filter,
                PacketHandler(move(primaryInjector), interface_prim, stats_manager, 0));
            secondary_session = make_unique<CaptureSession>(
                interface_secn, filter,
                PacketHandler(move(secondaryInjector), interface_secn, stats_manager, 0));

            thread prim_thread(&CaptureSession::startCapture, primary_session.get(), count);
            thread sec_thread(&CaptureSession::startCapture, secondary_session.get(), count);

            prim_thread.join();
            sec_thread.join();
        } else {
            auto injectionHandle = createPcapHandleWrapper(
                CaptureSession::createPcapHandle(interface_prim, filter));

            primary_session = make_unique<CaptureSession>(
                interface_prim, filter,
                PacketHandler(move(injectionHandle), interface_prim, stats_manager, 0));
            primary_session->startCapture(count);
        }

        stats_manager.print();
    }



    void stop() {
        if (primary_session) primary_session->stopCapture();
        if (secondary_session) secondary_session->stopCapture();

        cout << "\nCapture Statistics Report:";

        struct pcap_stat stats;

        if (primary_session && primary_session->getStats(stats)) {
            cout << ":\n" << primary_session->getInterfaceName() << ":\n"
                      << primary_session->getPacketHandler().getPacketsProcessed() << " packets processed\n"
                      << stats.ps_recv << " packets received by filter\n"
                      << stats.ps_drop << " packets dropped\n\n";
        }

        if (secondary_session && secondary_session->getStats(stats)) {
            cout << secondary_session->getInterfaceName() << ":\n"
                      << secondary_session->getPacketHandler().getPacketsProcessed() << " packets processed\n"
                      << stats.ps_recv << " packets received by filter\n"
                      << stats.ps_drop << " packets dropped\n\n";
        }



        stats_manager.print(); // Print other statistics

        if (!interface_secn.empty()){
            cout << "\nInjection Statistics Report:\n";
            cout << left
                    << setw(22) << "ReceivedOnInterface"
                    << setw(17) << "PacketsInjected"
                    << setw(10) << "Failures"
                    << "SuccessRate (%)\n";

            if (primary_session) {
                primary_session->getPacketHandler().printInjectionStatistics();
            }
            if (secondary_session) {
                secondary_session->getPacketHandler().printInjectionStatistics();
            }
        }


        cout << "Capture stopped. Exiting gracefully...\n";
        exit(0);
    }

    void parseArguments(int argc, char* argv[]) {
        int opt;
        while ((opt = getopt(argc, argv, "hi:j:n:")) != -1) {
            switch (opt) {
                case 'h':
                    cout << "Usage: " << argv[0]
                              << " [-h] [-i primary_interface] [-j secondary_interface] [-n packet_count] [BPF filter]\n";
                    exit(0);
                case 'i':
                    interface_prim = optarg;
                    break;
                case 'j':
                    interface_secn = optarg;
                    break;
                case 'n':
                    count = stoi(optarg);
                    break;
                default:
                    cerr << "Unknown option: " << char(opt) << "\n";
                    exit(1);
            }
        }

        for (int i = optind; i < argc; i++) {
            filter += argv[i];
            filter += " ";
        }
    }
};

Application* global_app = nullptr;

int main(int argc, char* argv[]) {
    Application app;
    global_app = &app; // Set the global application pointer for signal handling

    // Set up signal handlers
    signal(SIGINT, [](int signo) { if (global_app) global_app->stop(); });
    signal(SIGTERM, [](int signo) { if (global_app) global_app->stop(); });
    signal(SIGQUIT, [](int signo) { if (global_app) global_app->stop(); });

    app.run(argc, argv);
    return 0;
}
