/**
 * seq_tracker.h — TCP flow state tracker.
 *
 * WHY THIS EXISTS:
 * A DPI bypass strategy (like splitting ClientHello or injecting junk packets)
 * must only run ONCE per TCP flow — when the ClientHello handshake packet is seen.
 * Applying bypass techniques to normal HTTP/TLS data streams would corrupt the TCP stream
 * or dramatically impact performance.
 * This class tracks active TCP sessions (keyed by 4-tuple) and stores their current sequence/ack state
 * along with whether a bypass has been applied. It also includes an expiration mechanism for stale sessions.
 */
#pragma once

#include <cstdint>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <optional>

struct TcpSessionKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const TcpSessionKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port;
    }
};

struct TcpSessionKeyHash {
    std::size_t operator()(const TcpSessionKey& k) const {
        // Simple FNV-1a hash
        std::size_t h = 2166136261u;
        h = (h ^ k.src_ip) * 16777619u;
        h = (h ^ k.dst_ip) * 16777619u;
        h = (h ^ k.src_port) * 16777619u;
        h = (h ^ k.dst_port) * 16777619u;
        return h;
    }
};

struct TcpSessionState {
    bool bypass_applied = false;
    uint32_t last_seq = 0;
    uint32_t last_ack = 0;
    std::chrono::steady_clock::time_point last_seen;
};

class SeqTracker {
public:
    SeqTracker() = default;
    ~SeqTracker() = default;

    // Registers/updates a TCP flow packet's SEQ/ACK values
    void Update(const TcpSessionKey& key, uint32_t seq, uint32_t ack, uint8_t flags);

    // Checks if a desync strategy has already been executed on this flow
    bool IsBypassApplied(const TcpSessionKey& key) const;

    // Flags the connection as successfully desynchronized
    void MarkBypassed(const TcpSessionKey& key);

    // Retrieves the current sequence number for generating matching junk packets
    std::optional<uint32_t> GetClientSeq(const TcpSessionKey& key) const;

    // Removes old session states to prevent memory leaks
    void ExpireStale(std::chrono::seconds max_age = std::chrono::seconds(180));

    // Disable copy
    SeqTracker(const SeqTracker&) = delete;
    SeqTracker& operator=(const SeqTracker&) = delete;

private:
    mutable std::mutex mutex_;
    std::unordered_map<TcpSessionKey, TcpSessionState, TcpSessionKeyHash> sessions_;
};
