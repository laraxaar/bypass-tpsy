#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include "../include/wfp_manager.h"
#include "../include/config_manager.h"

// Modules (Linked via CMake)
#include "proxy_server.cpp"
#include "ui_manager.cpp"
#include "dns_resolver.cpp"

int main() {
    // 1. Load config and resolve dynamic app paths (PID/PEB logic)
    AppConfig config = ConfigManager::LoadConfig("config.json");
    if (config.whitelist.empty()) {
        std::cerr << "[-] Error: Whitelist is empty or targets not running." << std::endl;
    }

    // 2. Initialize WFP Redirection (WhiteList mode)
    WFPManager wfp;
    if (wfp.Initialize()) {
        // Redirection for TCP/UDP 443 and UDP 53
        if (wfp.SetupRedirection(8888, config.whitelist)) {
            std::cout << "[+] WFP active for " << config.whitelist.size() << " apps." << std::endl;
        }
    } else {
        std::cerr << "[-] Access Denied: Admin required!" << std::endl;
        return 1;
    }

    // 3. Initialize engine pool
    AdvancedBypass::SetJunkPool(config.junk_pool);

    // 4. Start Daemons
    DoHResolver dns;
    dns.StartDNSServer();

    std::thread proxyThread([]() {
        ProxyServer proxy;
        proxy.Start();
    });
    proxyThread.detach();

    // 5. Start Tray Interface
    UIManager ui;
    ui.Start();

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    wfp.Cleanup();
    return 0;
}
