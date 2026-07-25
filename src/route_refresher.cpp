#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// СТРОГИЙ ПОРЯДОК ДЛЯ СЕТЕВОГО СТЕКА WINDOWS (гасит ошибки в netioapi.h)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <ntstatus.h>
#include <netioapi.h>
#include <iphlpapi.h>

// Теперь безопасно подключаем локальные инклуды проекта
#include "route_refresher.h"
#include "logger.h"
#include "stats.h"
#include <chrono>
#include <algorithm> // Для std::sort

RouteRefresher::RouteRefresher(DnsProxy& dns, RouteTable& routes, const Config& cfg)
    : dns_(dns), routes_(routes), cfg_(cfg) {
    target_hosts_ = cfg.GetHosts();
}

RouteRefresher::~RouteRefresher() {
    Stop();
}

void RouteRefresher::Start() {
    if (!cfg_.GetBool("route_refresh", "enabled", true)) {
        LOG_INFO("Route refresher background thread is disabled in config");
        // Mark as resolved immediately to unblock main loop
        {
            std::lock_guard lock(init_mutex_);
            initial_resolved_ = true;
        }
        init_cv_.notify_all();
        return;
    }

    Stop();
    thread_ = std::jthread([this](std::stop_token stop) {
        RefreshLoop(stop);
    });
}

void RouteRefresher::Stop() {
    if (thread_.joinable()) {
        thread_.request_stop();
        thread_.join();
    }
}

void RouteRefresher::WaitForInitialResolve() {
    std::unique_lock lock(init_mutex_);
    init_cv_.wait(lock, [this] { return initial_resolved_; });
}

void RouteRefresher::PerformRefresh() {
    bool any_changed = false;
    uint32_t stabilize_sec = static_cast<uint32_t>(cfg_.GetInt("route_refresh", "stabilize_seconds", 30));

    for (const auto& host : target_hosts_) {
        // Fetch new IPs
        std::vector<uint32_t> new_ips = dns_.ResolveNow(host);
        if (new_ips.empty()) {
            LOG_WARN2("Failed to resolve target domain during refresh", host);
            continue;
        }

        // Fetch currently routed IPs
        std::vector<uint32_t> current_ips = routes_.GetHostIPs(host);

        // Sort to compare
        std::vector<uint32_t> new_ips_sorted = new_ips;
        std::vector<uint32_t> current_ips_sorted = current_ips;
        std::sort(new_ips_sorted.begin(), new_ips_sorted.end());
        std::sort(current_ips_sorted.begin(), current_ips_sorted.end());

        if (new_ips_sorted != current_ips_sorted) {
            any_changed = true;
            LOG_INFO2("DNS IP change detected for domain", host + ". Applying routes updates...");
            
            // Basic stabilization logic: wait a few seconds, then update routes
            if (stabilize_sec > 0) {
                std::this_thread::sleep_for(std::chrono::seconds(stabilize_sec));
            }

            routes_.AddHostRoutes(host, new_ips);
            BypassStats::Get().route_updates++;
        }
    }

    if (!any_changed) {
        LOG_DEBUG("Route refresh completed: no route table changes needed");
    }
}

void RouteRefresher::RefreshLoop(std::stop_token stop) {
    LOG_INFO("Route refresher background thread started");

    // Perform initial resolve and unblock main
    PerformRefresh();
    {
        std::lock_guard lock(init_mutex_);
        initial_resolved_ = true;
    }
    init_cv_.notify_all();

    uint32_t interval_min = static_cast<uint32_t>(cfg_.GetInt("route_refresh", "interval_min", 5));
    if (interval_min == 0) interval_min = 5;

    while (!stop.stop_requested()) {
        // Sleep in small increments to respond to shutdown requests rapidly
        for (uint32_t i = 0; i < interval_min * 60; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (stop.stop_requested()) return;
        }

        PerformRefresh();
    }
}