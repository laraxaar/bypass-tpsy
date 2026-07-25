/**
 * stats.h — Thread-safe statistics tracking.
 *
 * WHY THIS EXISTS:
 * DPI bypass engines need visibility into their packet interception and drop rates.
 * Without structured metrics, diagnosing whether a bypass strategy is failing,
 * whether host rules are too wide or too narrow, or whether QUIC is being fallback-triggered
 * is impossible. This module provides atomic metrics counters and a background thread
 * to print them regularly at a configurable interval.
 */
#pragma once

#include <atomic>
#include <thread>
#include <string>

class BypassStats {
public:
    std::atomic<uint64_t> packets_captured{0};
    std::atomic<uint64_t> packets_bypassed{0};     // Strategy applied
    std::atomic<uint64_t> packets_passthrough{0};  // Transmitted untouched
    std::atomic<uint64_t> packets_quic_dropped{0}; // QUIC packets dropped to force TCP fallback
    std::atomic<uint64_t> tls_parsed_ok{0};
    std::atomic<uint64_t> tls_parse_failed{0};
    std::atomic<uint64_t> sni_matched{0};
    std::atomic<uint64_t> sni_not_matched{0};
    std::atomic<uint64_t> dns_queries{0};
    std::atomic<uint64_t> dns_cache_hits{0};
    std::atomic<uint64_t> dns_doh_queries{0};
    std::atomic<uint64_t> route_updates{0};
    std::atomic<uint64_t> strategy_errors{0};

    static BypassStats& Get();

    void StartReporter(uint32_t interval_sec);
    void StopReporter();

    // Non-copyable
    BypassStats(const BypassStats&) = delete;
    BypassStats& operator=(const BypassStats&) = delete;

private:
    BypassStats() = default;
    ~BypassStats();

    std::jthread reporter_thread_;
    void ReportLoop(std::stop_token stop, uint32_t interval_sec);
};
