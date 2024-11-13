#include "Application.h"
#include <csignal>

int main(int argc, char* argv[]) {
    Application app;
    global_app = &app; // Set global application pointer

    // Set up signal handlers
    signal(SIGINT, [](int) { if (global_app) global_app->stop(); });
    signal(SIGTERM, [](int) { if (global_app) global_app->stop(); });
    signal(SIGQUIT, [](int) { if (global_app) global_app->stop(); });

    app.run(argc, argv);
    return 0;
}
