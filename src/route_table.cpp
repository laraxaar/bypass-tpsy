#include "route_table.h"
#include "logger.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

// Helper to convert subnet mask to prefix length
static BYTE SubnetMaskToPrefixLength(uint32_t mask) {
    BYTE length = 0;
    while (mask) {
        length += (mask & 1);
        mask >>= 1;
    }
    return length;
}

RouteTable::RouteTable(NET_LUID tunnel_luid, uint32_t tunnel_ifindex)
    : tunnel_luid_(tunnel_luid), tunnel_ifindex_(tunnel_ifindex) {}

RouteTable::~RouteTable() {
    CleanupAll();
}

bool RouteTable::AddRouteEntry(uint32_t dest, uint32_t mask, uint32_t metric) {
    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);

    row.InterfaceLuid = tunnel_luid_;
    row.InterfaceIndex = tunnel_ifindex_;
    
    row.DestinationPrefix.Prefix.si_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = htonl(dest);
    row.DestinationPrefix.PrefixLength = SubnetMaskToPrefixLength(mask);
    
    // Low metric makes this route higher priority than default gateway
    row.Metric = metric;

    DWORD err = CreateIpForwardEntry2(&row);
    if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
        LOG_ERROR2("Failed to add route table entry", "Code " + std::to_string(err));
        return false;
    }

    return true;
}

bool RouteTable::DeleteRouteEntry(uint32_t dest, uint32_t mask) {
    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);

    row.InterfaceLuid = tunnel_luid_;
    row.InterfaceIndex = tunnel_ifindex_;
    
    row.DestinationPrefix.Prefix.si_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = htonl(dest);
    row.DestinationPrefix.PrefixLength = SubnetMaskToPrefixLength(mask);

    DWORD err = DeleteIpForwardEntry2(&row);
    if (err != NO_ERROR && err != ERROR_NOT_FOUND) {
        LOG_ERROR2("Failed to delete route table entry", "Code " + std::to_string(err));
        return false;
    }

    return true;
}

bool RouteTable::AddRoute(uint32_t network_ip_host, uint32_t subnet_mask, uint32_t metric) {
    std::lock_guard lock(mutex_);
    
    IN_ADDR ip_struct, mask_struct;
    ip_struct.S_un.S_addr = htonl(network_ip_host);
    mask_struct.S_un.S_addr = htonl(subnet_mask);
    
    char ip_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_struct, ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &mask_struct, mask_str, INET_ADDRSTRLEN);

    LOG_INFO2("Adding static Wintun route", std::string(ip_str) + "/" + mask_str);
    
    if (AddRouteEntry(network_ip_host, subnet_mask, metric)) {
        static_routes_.push_back({network_ip_host, subnet_mask});
        return true;
    }
    return false;
}

bool RouteTable::RemoveRoute(uint32_t network_ip_host, uint32_t subnet_mask) {
    std::lock_guard lock(mutex_);
    
    DeleteRouteEntry(network_ip_host, subnet_mask);

    for (auto it = static_routes_.begin(); it != static_routes_.end(); ++it) {
        if (it->dest == network_ip_host && it->mask == subnet_mask) {
            static_routes_.erase(it);
            return true;
        }
    }
    return false;
}

void RouteTable::AddHostRoutes(const std::string& hostname, const std::vector<uint32_t>& ips) {
    std::lock_guard lock(mutex_);
    
    std::vector<uint32_t> added_ips;
    for (uint32_t ip : ips) {
        // Add host route (/32 mask = 0xFFFFFFFF)
        if (AddRouteEntry(ip, 0xFFFFFFFF, 5)) {
            added_ips.push_back(ip);
        }
    }

    if (!added_ips.empty()) {
        // If there were routes previously mapped to this host, clean them up first
        auto prev_it = host_routes_.find(hostname);
        if (prev_it != host_routes_.end()) {
            for (uint32_t old_ip : prev_it->second) {
                // If old IP isn't in the new list, remove it from system
                if (std::find(ips.begin(), ips.end(), old_ip) == ips.end()) {
                    DeleteRouteEntry(old_ip, 0xFFFFFFFF);
                }
            }
        }
        host_routes_[hostname] = added_ips;
    }
}

void RouteTable::RemoveHostRoutes(const std::string& hostname) {
    std::lock_guard lock(mutex_);
    auto it = host_routes_.find(hostname);
    if (it != host_routes_.end()) {
        for (uint32_t ip : it->second) {
            DeleteRouteEntry(ip, 0xFFFFFFFF);
        }
        host_routes_.erase(it);
    }
}

std::vector<uint32_t> RouteTable::GetHostIPs(const std::string& hostname) const {
    std::lock_guard lock(mutex_);
    auto it = host_routes_.find(hostname);
    if (it != host_routes_.end()) {
        return it->second;
    }
    return {};
}

void RouteTable::CleanupAll() {
    std::lock_guard lock(mutex_);
    
    if (!static_routes_.empty() || !host_routes_.empty()) {
        LOG_INFO("Cleaning up route table entries...");
    }

    for (const auto& route : static_routes_) {
        DeleteRouteEntry(route.dest, route.mask);
    }
    static_routes_.clear();

    for (const auto& [host, ips] : host_routes_) {
        for (uint32_t ip : ips) {
            DeleteRouteEntry(ip, 0xFFFFFFFF);
        }
    }
    host_routes_.clear();
}
