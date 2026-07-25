#include "stats.h"
#include "logger.h"
#include <chrono>

BypassStats& BypassStats::Get() {
    static BypassStats instance;
    return instance;
}

BypassStats::~BypassStats() {
    StopReporter();
}

void BypassStats::StartReporter(uint32_t interval_sec) {
    if (interval_sec == 0) return;
    StopReporter();
    reporter_thread_ = std::jthread([this, interval_sec](std::stop_token stop) {
        ReportLoop(stop, interval_sec);
    });
}

void BypassStats::StopReporter() {
    if (reporter_thread_.joinable()) {
        reporter_thread_.request_stop();
        reporter_thread_.join();
    }
}

void BypassStats::ReportLoop(std::stop_token stop, uint32_t interval_sec) {
    LOG_INFO2("Stats reporter thread started", std::to_string(interval_sec) + "s interval");
    while (!stop.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::seconds(interval_sec));
        if (stop.stop_requested()) break;

        uint64_t cap = packets_captured.load();
        uint64_t byp = packets_bypassed.load();
        uint64_t pass = packets_passthrough.load();
        uint64_t quic = packets_quic_dropped.load();
        uint64_t parsed_ok = tls_parsed_ok.load();
        uint64_t sni_match = sni_matched.load();
        uint64_t dns_q = dns_queries.load();
        uint64_t dns_ch = dns_cache_hits.load();
        uint64_t dns_doh = dns_doh_queries.load();
        uint64_t routes = route_updates.load();
        uint64_t errs = strategy_errors.load();

        std::string stat_line = 
            "Cap=" + std::to_string(cap) + 
            " Byp=" + std::to_string(byp) + 
            " Pass=" + std::to_string(pass) + 
            " QUIC_Drop=" + std::to_string(quic) + 
            " TLS_Ok=" + std::to_string(parsed_ok) + 
            " SNI_Match=" + std::to_string(sni_match) + 
            " DNS_Q=" + std::to_string(dns_q) + 
            " DNS_Hit=" + std::to_string(dns_ch) + 
            " DoH=" + std::to_string(dns_doh) + 
            " Route_Up=" + std::to_string(routes) + 
            " Errs=" + std::to_string(errs);

        LOG_INFO2("[STATS]", stat_line);

        // Warning heuristics
        if (byp > 0 && errs * 100 / byp > 10) {
            LOG_WARN("Strategy error rate is higher than 10%! Check if WinDivert is running correctly.");
        }
        if (parsed_ok > 10 && sni_match * 100 / parsed_ok < 20) {
            LOG_WARN("Less than 20% of parsed TLS SNIs match the filter. Verify your host_filter patterns.");
        }
    }
}
