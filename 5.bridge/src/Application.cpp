#include "Application.h"
#include <iostream>
#include <thread>
#include <csignal>
#include "pcap_utils.h"

Application* global_app = nullptr; // Global pointer for signal handling

void Application::run(int argc, char* argv[]) {

    global_app = this;

    parseArguments(argc, argv);

    if (interface_prim.empty()) {
        std::cerr << "At least one interface must be specified using -i.\n";
        return;
    }

    if (!interface_secn.empty()) {
        // For dual-interface operation
        auto primaryInjector = createPcapHandleWrapper(
            CaptureSession::createPcapHandle(interface_secn, filter));
        auto secondaryInjector = createPcapHandleWrapper(
            CaptureSession::createPcapHandle(interface_prim, filter));

        primary_session = std::make_unique<CaptureSession>(
            interface_prim, filter,
            PacketHandler(std::move(primaryInjector), interface_prim, stats_manager));
        secondary_session = std::make_unique<CaptureSession>(
            interface_secn, filter,
            PacketHandler(std::move(secondaryInjector), interface_secn, stats_manager));

        // Run capture sessions in separate threads
        std::thread prim_thread(&CaptureSession::startCapture, primary_session.get(), count);
        std::thread sec_thread(&CaptureSession::startCapture, secondary_session.get(), count);

        prim_thread.join();
        sec_thread.join();
    } else {
        // For single-interface operation
        auto injectionHandle = createPcapHandleWrapper(
            CaptureSession::createPcapHandle(interface_prim, filter));

        primary_session = std::make_unique<CaptureSession>(
            interface_prim, filter,
            PacketHandler(std::move(injectionHandle), interface_prim, stats_manager));
        primary_session->startCapture(count);
    }

    stop();
}

void Application::stop() {
    if (primary_session) primary_session->stopCapture();
    if (secondary_session) secondary_session->stopCapture();

    std::cout << "\nCapture Statistics Report:";

    struct pcap_stat stats;

    if (primary_session && primary_session->getStats(stats)) {
        std::cout << ":\n" << primary_session->getInterfaceName() << ":\n"
                  << primary_session->getPacketHandler().getPacketsProcessed() << " packets processed\n"
                  << stats.ps_recv << " packets received by filter\n"
                  << stats.ps_drop << " packets dropped\n\n";
    }

    if (secondary_session && secondary_session->getStats(stats)) {
        std::cout << secondary_session->getInterfaceName() << ":\n"
                  << secondary_session->getPacketHandler().getPacketsProcessed() << " packets processed\n"
                  << stats.ps_recv << " packets received by filter\n"
                  << stats.ps_drop << " packets dropped\n\n";
    }

    stats_manager.print(); // Print overall statistics

    if (!interface_secn.empty()) {
        std::cout << "\nInjection Statistics Report:\n";
        std::cout << std::left
                  << std::setw(22) << "ReceivedOnInterface"
                  << std::setw(21) << "PacketsInjectedFrom"
                  << std::setw(10) << "Failures"
                  << "SuccessRate (%)\n";

        if (primary_session) {
            primary_session->getPacketHandler().print();
        }
        if (secondary_session) {
            secondary_session->getPacketHandler().print();
        }
    }

    std::cout << "Capture stopped. Exiting gracefully...\n";
    exit(0);
}

void Application::parseArguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-i" && i + 1 < argc) {
            interface_prim = argv[++i];
        } else if (arg == "-j" && i + 1 < argc) {
            interface_secn = argv[++i];
        } else if (arg == "-n" && i + 1 < argc) {
            count = std::stoi(argv[++i]);
        } else if (arg == "-h") {
            std::cout << "Usage: " << argv[0]
                      << " [-h] [-i primary_interface] [-j secondary_interface] [-n packet_count] [BPF filter]\n";
            exit(0);
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            exit(1);
        } else {
            filter += arg + " ";
        }
    }
}
