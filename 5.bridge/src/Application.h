#ifndef APPLICATION_H
#define APPLICATION_H

#include <string>
#include <memory>
#include "CaptureSession.h"
#include "StatisticsManager.h"

class Application {
private:
    std::string interface_prim;
    std::string interface_secn;
    std::string filter;
    int count = 0;
    StatisticsManager stats_manager;

    std::unique_ptr<CaptureSession> primary_session;
    std::unique_ptr<CaptureSession> secondary_session;

public:
    /**
     * Runs the application with the provided command-line arguments.
     * @param argc Number of arguments.
     * @param argv Array of arguments.
     */
    void run(int argc, char* argv[]);

    /**
     * Stops the application and any ongoing packet capture.
     */
    void stop();

private:
    /**
     * Parses command-line arguments to configure the application.
     * @param argc Number of arguments.
     * @param argv Array of arguments.
     */
    void parseArguments(int argc, char* argv[]);
};

extern Application* global_app; // Declare the global pointer

#endif // APPLICATION_H
