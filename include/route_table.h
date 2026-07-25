/**
 * route_table.h — Dynamic route management.
 *
 * WHY THIS EXISTS:
 * Unlike WFP which was incorrectly configured in the original code, this engine
 * redirects traffic selectively using the Windows Route Table. We only route
 * traffic for blocked networks or hosts through our Wintun adapter.
 * The system handles two types of routes:
 *   1. Static routes (IP ranges from config).
 *   2. Dynamic routes (IPs resolved on-the-fly for targeted hostnames).
 * To prevent orphaned routes on unexpected shutdowns, this module utilizes RAII,
 * a global instance with standard custom exit handlers (atexit, Ctrl+C handler),
 * and completely cleans up the route entries upon termination.
 */
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <netioapi.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>

class RouteTable {
public:
    RouteTable(NET_LUID tunnel_luid, uint32_t tunnel_ifindex);
    ~RouteTable();

    // Adds a persistent route via Wintun
    bool AddRoute(uint32_t network_ip_host, uint32_t subnet_mask, uint32_t metric = 5);
    bool RemoveRoute(uint32_t network_ip_host, uint32_t subnet_mask);

    // Dynamic hostname routes management
    void AddHostRoutes(const std::string& hostname, const std::vector<uint32_t>& ips);
    void RemoveHostRoutes(const std::string& hostname);

    std::vector<uint32_t> GetHostIPs(const std::string& hostname) const;

    // Cleans up all added routes. Safe to call multiple times.
    void CleanupAll();

    // Disable copy
    RouteTable(const RouteTable&) = delete;
    RouteTable& operator=(const RouteTable&) = delete;

private:
    struct RouteEntry {
        uint32_t dest;
        uint32_t mask;
    };

    NET_LUID tunnel_luid_;
    uint32_t tunnel_ifindex_;
    mutable std::mutex mutex_;

    std::vector<RouteEntry> static_routes_;
    std::unordered_map<std::string, std::vector<uint32_t>> host_routes_;

    bool AddRouteEntry(uint32_t dest, uint32_t mask, uint32_t metric);
    bool DeleteRouteEntry(uint32_t dest, uint32_t mask);
};
