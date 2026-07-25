/**
 * dns_proxy.h — Transparent packet-level DNS interceptor and DoH client.
 *
 * WHY THIS EXISTS:
 * Changing system-wide DNS settings via netsh is unstable and easily overridden by other software.
 * In this architecture, DNS requests are captured at the network layer. We add a route for a target DNS server
 * (e.g. 8.8.8.8) through Wintun. When the browser sends a DNS query, it lands in Wintun.
 * The main loop intercepts UDP port 53 packets, passes them to this module, which:
 *   1. Extracts the queried domain name.
 *   2. Checks if the domain is blocked.
 *   3. If blocked: performs a secure DNS-over-HTTPS (DoH) request using WinHTTP,
 *      stores the result in a TTL-aware cache, and constructs a raw DNS UDP response.
 *   4. If not blocked: forwards the request to the system's real resolver,
 *      and constructs a normal DNS UDP response.
 * This completely prevents DNS poisoning/spoofing without breaking system-wide DNS configuration.
 */
#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <optional>
#include <span>
#include "config.h"
#include "packet.h"

class DnsProxy {
public:
    explicit DnsProxy(const Config& cfg);
    ~DnsProxy();

    // Processes a raw IPv4 UDP port 53 packet.
    // If it's a valid DNS query, returns a completed raw IPv4 UDP DNS response packet to write back to Wintun.
    std::optional<std::vector<uint8_t>> ProcessDnsPacket(const uint8_t* raw_packet, uint32_t len);

    // Explicitly resolves a hostname via DoH and updates cache (used by RouteRefresher)
    std::vector<uint32_t> ResolveNow(const std::string& hostname);

    // Queries the DNS cache directly (used by RouteRefresher)
    std::vector<uint32_t> GetCachedIPs(const std::string& hostname) const;

    // Returns all hostnames currently registered in the cache
    std::vector<std::string> GetCachedHosts() const;

private:
    struct CacheEntry {
        std::vector<uint32_t> ips;
        std::chrono::steady_clock::time_point expires;
    };

    std::string doh_url_;
    std::string doh_host_;
    std::string doh_path_;
    
    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
    const Config& cfg_;

    // DoH Upstream Client
    std::vector<uint8_t> QueryDoH(const std::vector<uint8_t>& dns_wire_query);

    // DNS Packet helpers
    std::optional<std::string> ParseDnsQuestion(const uint8_t* dns_payload, uint32_t len, uint16_t& out_tx_id);
    std::vector<uint8_t> BuildDnsResponse(uint16_t tx_id, const std::string& name, const std::vector<uint32_t>& ips, uint32_t ttl = 300);

    void ParseDoHUrl(const std::string& url);
};
