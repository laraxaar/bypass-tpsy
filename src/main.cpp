/**
 * main.cpp — Hybrid Wintun + WinDivert DPI Evasion Engine Event Loop (Upgraded Logging).
 *
 * WHY THIS EXISTS:
 * This coordinates the hybrid packet inspection. This upgraded version contains extensive
 * LOG_TRACE and LOG_DEBUG instrumentation to provide full correlation auditing:
 * matching "what the code intends to do" (calculating checksums, sequence splits, fake injects)
 * with the byte-by-byte trace of what physically leaves the network adapters.
 */

// 1. Защита от мусора
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Изолируем макросы статусов windows.h, чтобы они не дрались с ntstatus.h
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif

// 2. ЖЕСТКИЙ ПОРЯДОК INCLUDES (Магия MSVC)
#include <windows.h>
#include <winsock2.h>

// Сбрасываем изоляцию для чистой загрузки остальных сетевых библиотек
#undef WIN32_NO_STATUS
#include <ws2tcpip.h> // Обязательно для inet_ntop!
#include <iphlpapi.h> // Обязательно для работы с маршрутами и адаптерами

// 4. И только потом C++ стандартная библиотека
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <csignal>
#include <sstream>
#include <algorithm>

// 5. Твои локальные файлы проекта
#include "logger.h"
#include "config.h"
#include "packet.h"
#include "tls_parser.h"
#include "quic_parser.h"
#include "dns_proxy.h"
#include "tunnel_io.h"
#include "inject_io.h"
#include "route_table.h"
#include "route_refresher.h"
#include "seq_tracker.h"
#include "bypass_strategy.h"
#include "stats.h"
#include "resource_extractor.h"

std::atomic<bool> g_shutdown{false};
RouteTable* g_route_table_ptr = nullptr;

// Format IP string from network order uint32_t
std::string IpToString(uint32_t ip) {
    IN_ADDR addr;
    addr.S_un.S_addr = ip;
    char buf[16];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

// Convert TCP flags byte to human-readable string
std::string FlagsToString(uint8_t flags) {
    std::string s = "";
    if (flags & TcpFlags::SYN) s += "SYN ";
    if (flags & TcpFlags::ACK) s += "ACK ";
    if (flags & TcpFlags::PSH) s += "PSH ";
    if (flags & TcpFlags::FIN) s += "FIN ";
    if (flags & TcpFlags::RST) s += "RST ";
    if (flags & TcpFlags::URG) s += "URG ";
    if (s.empty()) s = "NONE";
    return s;
}

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT || ctrl_type == CTRL_CLOSE_EVENT) {
        LOG_INFO("Shutdown signal received. Restoring route table...");
        g_shutdown = true;
        if (g_route_table_ptr) {
            g_route_table_ptr->CleanupAll();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        return TRUE;
    }
    return FALSE;
}

int main() {
    // 0. Extract embedded dependencies
    ExtractEmbeddedDependencies();

    // 1. Initialize configuration
    std::string config_file = "config.ini";
    Config cfg(config_file);

    // 2. Initialize logger with upgraded levels
    std::string log_level_str = cfg.GetString("logging", "level", "info");
    LogLevel level = LogLevel::Info;
    if (log_level_str == "trace") level = LogLevel::Trace;
    else if (log_level_str == "debug") level = LogLevel::Debug;
    else if (log_level_str == "warn") level = LogLevel::Warn;
    else if (log_level_str == "error") level = LogLevel::Error;

    std::string log_file = cfg.GetString("logging", "file", "");
    Logger::Get().Init(level, log_file);

    LOG_INFO("==================================================");
    LOG_INFO("Bypass TSPY v4.0 — Wintun & WinDivert Hybrid Engine");
    LOG_INFO("==================================================");

    try {
        // 3. Initialize Wintun TUN adapter
        TunnelIO tunnel(cfg);

        // 4. Initialize WinDivert send-only socket
        InjectIO inject(cfg);

        // 5. Initialize Route Table and register safe exit handler
        RouteTable routes(tunnel.GetAdapterLuid(), tunnel.GetAdapterIndex());
        g_route_table_ptr = &routes;
        SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

        // Add static routes from config
        auto static_subnets = cfg.GetSubnets();
        for (const auto& subnet : static_subnets) {
            routes.AddRoute(subnet.first, subnet.second);
        }

        // Route target DNS resolver 8.8.8.8 through Wintun for transparent proxying
        LOG_INFO("Routing target DNS resolver 8.8.8.8 through Wintun for transparent interception...");
        routes.AddRoute(0x08080808, 0xFFFFFFFF, 1); // 8.8.8.8/32

        // 6. Initialize DNS Proxy
        DnsProxy dns_proxy(cfg);

        // 7. Initialize Route Refresher and wait for initial lookup
        RouteRefresher refresher(dns_proxy, routes, cfg);
        refresher.Start();
        LOG_INFO("Waiting for initial DNS resolution of target hosts...");
        refresher.WaitForInitialResolve();

        // 8. Initialize stats reporter
        uint32_t stats_sec = static_cast<uint32_t>(cfg.GetInt("stats", "interval_sec", 60));
        BypassStats::Get().StartReporter(stats_sec);

        // 9. Initialize session tracker and bypass strategies
        SeqTracker tracker;
        auto strategy = CreateStrategy(cfg);
        LOG_INFO2("Loaded bypass strategy", strategy->Name());

        LOG_INFO("Bypass event loop running. Intercepting packets...");

        // 10. Main processing loop
        while (!g_shutdown) {
            auto opt_pkt = tunnel.Receive(100);
            if (!opt_pkt) continue;

            BypassStats::Get().packets_captured++;
            const uint8_t* raw_data = opt_pkt->data;
            uint32_t raw_len = opt_pkt->size;

            auto* ip = ParseIPv4(raw_data, raw_len);
            if (!ip) {
                LOG_TRACE2("[PACKET-DROP] Non-IPv4 or malformed IP header received. Size", std::to_string(raw_len));
                tunnel.Release(*opt_pkt);
                continue;
            }

            std::string src_ip_str = IpToString(ip->src_addr);
            std::string dst_ip_str = IpToString(ip->dst_addr);

            LOG_TRACE2("[FLOW-IP] Packet received from TUN", 
                src_ip_str + " -> " + dst_ip_str + ", Proto=" + std::to_string(ip->protocol) + ", TTL=" + std::to_string(ip->ttl));

            // --- DNS Query Interception (dest UDP 53) ---
            if (ip->protocol == 17) { // UDP
                auto* udp = ParseUDP(ip, raw_len);
                if (udp && ntohs(udp->dst_port) == 53) {
                    LOG_DEBUG2("[DNS-INTERCEPT] Intercepted DNS query packet", src_ip_str + ":" + std::to_string(ntohs(udp->src_port)));
                    
                    auto opt_dns_resp = dns_proxy.ProcessDnsPacket(raw_data, raw_len);
                    if (opt_dns_resp) {
                        LOG_DEBUG2("[DNS-PROXY] Generated DNS answer local injection", "Size=" + std::to_string(opt_dns_resp->size()) + " bytes");
                        
                        if (Logger::Get().GetLevel() <= LogLevel::Trace) {
                            LOG_TRACE(Logger::HexDump(opt_dns_resp->data(), opt_dns_resp->size()));
                        }

                        // Inject response packet back into the local OS
                        tunnel.Send(opt_dns_resp->data(), static_cast<uint32_t>(opt_dns_resp->size()));
                        BypassStats::Get().packets_bypassed++;
                    } else {
                        LOG_DEBUG("[DNS-PROXY] DNS response bypass failed. Forwarding to physical gateway...");
                        inject.Send(raw_data, raw_len);
                        BypassStats::Get().packets_passthrough++;
                    }
                    tunnel.Release(*opt_pkt);
                    continue;
                }

                // --- QUIC Evasion Drop Check (UDP port 443) ---
                if (udp && ntohs(udp->dst_port) == 443) {
                    auto udp_payload = GetUDPPayload(ip, udp, raw_len);
                    if (cfg.GetBool("quic", "block_quic", true) && IsQUICInitial(udp_payload)) {
                        LOG_DEBUG2("[QUIC-DETECT] Found QUIC Initial UDP:443 payload", "Size=" + std::to_string(udp_payload.size()) + " bytes");
                        
                        // Check if dest IP belongs to a resolved blocked host
                        bool matches_target = false;
                        uint32_t dest_ip = ntohl(ip->dst_addr);
                        for (const auto& host : cfg.GetHosts()) {
                            auto cached_ips = dns_proxy.GetCachedIPs(host);
                            if (std::find(cached_ips.begin(), cached_ips.end(), dest_ip) != cached_ips.end()) {
                                matches_target = true;
                                break;
                            }
                        }

                        if (matches_target) {
                            LOG_INFO2("[QUIC-DROP] Blocking QUIC packet to target host IP to force TCP fallback", dst_ip_str);
                            BypassStats::Get().packets_quic_dropped++;
                            tunnel.Release(*opt_pkt);
                            continue; // drop packet
                        }
                    }
                }

                // Normal UDP: forward unmodified
                LOG_TRACE("[FORWARD] Forwarding UDP packet to physical network");
                inject.Send(raw_data, raw_len);
                BypassStats::Get().packets_passthrough++;
                tunnel.Release(*opt_pkt);
                continue;
            }

            // --- TCP Interception (TCP port 443/80) ---
            if (ip->protocol == 6) { // TCP
                auto* tcp = ParseTCP(ip, raw_len);
                if (!tcp) {
                    LOG_TRACE("[FORWARD] Forwarding malformed TCP packet unmodified");
                    inject.Send(raw_data, raw_len);
                    BypassStats::Get().packets_passthrough++;
                    tunnel.Release(*opt_pkt);
                    continue;
                }

                uint32_t dest_port = ntohs(tcp->dst_port);
                auto tcp_payload = GetTCPPayload(ip, tcp, raw_len);

                // Update session state
                TcpSessionKey key{ip->src_addr, ip->dst_addr, tcp->src_port, tcp->dst_port};
                uint32_t seq = ntohl(tcp->seq_num);
                uint32_t ack = ntohl(tcp->ack_num);
                tracker.Update(key, seq, ack, tcp->flags);

                LOG_TRACE2("[FLOW-TCP-TRACK]", 
                    src_ip_str + ":" + std::to_string(ntohs(tcp->src_port)) + " -> " +
                    dst_ip_str + ":" + std::to_string(dest_port) + 
                    ", Seq=" + std::to_string(seq) + ", Ack=" + std::to_string(ack) + 
                    ", Flags=[" + FlagsToString(tcp->flags) + "]");

                bool bypass_applied = false;

                // Case 1: HTTPS Client Hello bypass
                if (dest_port == 443 && !tcp_payload.empty() && IsTLSHandshake(tcp_payload) && IsClientHello(tcp_payload)) {
                    BypassStats::Get().tls_parsed_ok++;
                    auto opt_sni = ExtractSNI(tcp_payload);
                    if (opt_sni) {
                        std::string sni = *opt_sni;
                        LOG_DEBUG2("[TLS-PARSE] Parsed TLS ClientHello SNI", sni);
                        
                        if (Logger::Get().GetLevel() <= LogLevel::Trace) {
                            LOG_TRACE(Logger::HexDump(tcp_payload.data(), tcp_payload.size()));
                        }

                        if (cfg.MatchesHostFilter(sni)) {
                            BypassStats::Get().sni_matched++;
                            if (!tracker.IsBypassApplied(key)) {
                                LOG_INFO2("[STRATEGY-TRIGGER] Domain matches filter. Applying evasion strategy", sni);
                                
                                auto bypass_res = strategy->Apply(raw_data, raw_len, ip, tcp, tcp_payload);
                                if (!bypass_res.packets.empty()) {
                                    tracker.MarkBypassed(key);
                                    for (size_t idx = 0; idx < bypass_res.packets.size(); ++idx) {
                                        const auto& out = bypass_res.packets[idx];
                                        
                                        LOG_DEBUG2("[INJECT-PACKET] Injecting generated segment " + std::to_string(idx + 1) + "/" + std::to_string(bypass_res.packets.size()), 
                                            "Size=" + std::to_string(out.data.size()) + " bytes, Delay=" + std::to_string(out.delay_ms) + "ms");
                                        
                                        if (Logger::Get().GetLevel() <= LogLevel::Trace) {
                                            LOG_TRACE(Logger::HexDump(out.data.data(), out.data.size()));
                                        }

                                        if (out.delay_ms > 0) {
                                            inject.SendDelayed(out.data.data(), static_cast<uint32_t>(out.data.size()), out.delay_ms);
                                        } else {
                                            inject.Send(out.data.data(), static_cast<uint32_t>(out.data.size()));
                                        }
                                    }
                                    BypassStats::Get().packets_bypassed++;
                                    bypass_applied = true;
                                } else {
                                    LOG_ERROR2("[STRATEGY-ERROR] Bypass strategy generated empty packet list for target", sni);
                                    BypassStats::Get().strategy_errors++;
                                }
                            } else {
                                LOG_TRACE("[STRATEGY-SKIP] Bypass already applied to this session. Ignoring subsequent handshake data.");
                            }
                        } else {
                            BypassStats::Get().sni_not_matched++;
                            LOG_DEBUG2("[FILTER-SKIP] SNI domain does not match whitelist", sni);
                        }
                    } else {
                        LOG_DEBUG("[TLS-PARSE] Failed to extract SNI extension from ClientHello record.");
                    }
                }
                // Case 2: HTTP Smuggler bypass (port 80)
                else if (dest_port == 80 && !tcp_payload.empty() && cfg.GetString("desync", "mode", "chain") == "http") {
                    if (!tracker.IsBypassApplied(key)) {
                        LOG_INFO2("[STRATEGY-TRIGGER] Port 80 HTTP payload seen. Applying HTTP smuggler", dst_ip_str);
                        
                        if (Logger::Get().GetLevel() <= LogLevel::Trace) {
                            LOG_TRACE(Logger::HexDump(tcp_payload.data(), tcp_payload.size()));
                        }

                        auto bypass_res = strategy->Apply(raw_data, raw_len, ip, tcp, tcp_payload);
                        if (!bypass_res.packets.empty()) {
                            tracker.MarkBypassed(key);
                            for (const auto& out : bypass_res.packets) {
                                if (Logger::Get().GetLevel() <= LogLevel::Trace) {
                                    LOG_TRACE(Logger::HexDump(out.data.data(), out.data.size()));
                                }
                                inject.Send(out.data.data(), static_cast<uint32_t>(out.data.size()));
                            }
                            BypassStats::Get().packets_bypassed++;
                            bypass_applied = true;
                        } else {
                            BypassStats::Get().strategy_errors++;
                        }
                    }
                }

                if (!bypass_applied) {
                    LOG_TRACE("[FORWARD] Forwarding TCP flow packet unmodified");
                    inject.Send(raw_data, raw_len);
                    BypassStats::Get().packets_passthrough++;
                }

                tunnel.Release(*opt_pkt);

                // Expire stale sessions periodically
                static auto last_cleanup = std::chrono::steady_clock::now();
                if (std::chrono::steady_clock::now() - last_cleanup > std::chrono::seconds(60)) {
                    tracker.ExpireStale();
                    last_cleanup = std::chrono::steady_clock::now();
                }
                continue;
            }

            // Non TCP/UDP: forward unmodified
            LOG_TRACE("[FORWARD] Forwarding non-TCP/UDP IP packet unmodified");
            inject.Send(raw_data, raw_len);
            BypassStats::Get().packets_passthrough++;
            tunnel.Release(*opt_pkt);
        }

        LOG_INFO("Bypass event loop stopped");
        BypassStats::Get().StopReporter();
        refresher.Stop();
        routes.CleanupAll();

    } catch (const std::exception& e) {
        LOG_ERROR2("Fatal engine error", e.what());
        if (g_route_table_ptr) {
            g_route_table_ptr->CleanupAll();
        }
        return 1;
    }

    LOG_INFO("Bypass TSPY terminated successfully");
    return 0;
}