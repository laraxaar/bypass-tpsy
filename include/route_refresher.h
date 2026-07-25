/**
 * route_refresher.h — Dynamic route refresher background service.
 *
 * WHY THIS EXISTS:
 * CDNs (like Cloudflare used by LinkedIn, etc.) rotate IP addresses frequently.
 * A static route added at startup will eventually point to dead IPs or fail to catch
 * the new IP. This module runs a background thread that periodically:
 *   1. Re-resolves all blocked domains configured in the INI file.
 *   2. Compares the fresh set of resolved IPs with currently routed IPs.
 *   3. If any change is detected, it handles route updates atomically after a configurable
 *      stabilization period (to handle round-robin DNS shifts smoothly).
 */
#pragma once

#include <thread>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>
#include "dns_proxy.h"
#include "route_table.h"
#include "config.h"

class RouteRefresher {
public:
    RouteRefresher(DnsProxy& dns, RouteTable& routes, const Config& cfg);
    ~RouteRefresher();

    void Start();
    void Stop();

    // Block until the initial DNS resolution of all targets completes
    void WaitForInitialResolve();

    // Disable copy
    RouteRefresher(const RouteRefresher&) = delete;
    RouteRefresher& operator=(const RouteRefresher&) = delete;

private:
    DnsProxy& dns_;
    RouteTable& routes_;
    const Config& cfg_;

    std::jthread thread_;
    std::vector<std::string> target_hosts_;
    
    std::mutex init_mutex_;
    std::condition_variable init_cv_;
    bool initial_resolved_ = false;

    void RefreshLoop(std::stop_token stop);
    void PerformRefresh();
};
