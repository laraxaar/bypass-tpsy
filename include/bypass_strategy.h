/**
 * bypass_strategy.h — DPI Bypass Strategies.
 *
 * WHY THIS EXISTS:
 * The original strategies (MSS limits, Out-of-order send on Stream socket,
 * fake TTL=2 socket writes) failed because they operated at the socket layer.
 * This module operates at the IP layer. It generates raw packets that are injected
 * via WinDivert.
 *
 * It implements modern techniques (RKN/TSPU bypass):
 *   1. DesyncSplit: splits the ClientHello packet into two TCP segments.
 *      DPI fails to reassemble them but the server successfully processes them.
 *   2. DesyncJunk: injects an out-of-window packet with TTL=1. It reaches only
 *      the DPI box (which parses it and falls into a desync state) and dies
 *      before reaching the target server.
 *   3. DesyncHttp: manipulates plaintext HTTP headers (NUL prefix, spacing).
 *   4. ChainDesync: allows combining strategies (e.g. junk followed by split).
 */
#pragma once

#include <vector>
#include <memory>
#include <span>
#include "packet.h"
#include "config.h"

struct PacketToSend {
    std::vector<uint8_t> data;
    uint32_t delay_ms = 0; // delay before injecting this packet
};

struct BypassResult {
    std::vector<PacketToSend> packets;
};

class IBypassStrategy {
public:
    virtual ~IBypassStrategy() = default;

    // Apply the strategy on a captured raw packet.
    // Returns a list of packets to inject. If bypass fails or is not applicable,
    // returns empty list (indicating main loop should fall back to normal forwarding).
    virtual BypassResult Apply(
        const uint8_t* original_packet, uint32_t packet_len,
        const IPv4Header* ip, const TCPHeader* tcp,
        std::span<const uint8_t> tcp_payload
    ) = 0;

    virtual const char* Name() const = 0;
};

// --- Concrete Strategies ---

class DesyncSplitStrategy : public IBypassStrategy {
public:
    explicit DesyncSplitStrategy(const Config& cfg);
    BypassResult Apply(const uint8_t* original_packet, uint32_t packet_len,
                       const IPv4Header* ip, const TCPHeader* tcp,
                       std::span<const uint8_t> tcp_payload) override;
    const char* Name() const override { return "DesyncSplit"; }

private:
    uint32_t split_offset_ = 0;
    uint32_t split_delay_ms_ = 0;
};

class DesyncJunkStrategy : public IBypassStrategy {
public:
    explicit DesyncJunkStrategy(const Config& cfg);
    BypassResult Apply(const uint8_t* original_packet, uint32_t packet_len,
                       const IPv4Header* ip, const TCPHeader* tcp,
                       std::span<const uint8_t> tcp_payload) override;
    const char* Name() const override { return "DesyncJunk"; }

private:
    uint32_t junk_size_ = 32;
    uint8_t junk_ttl_ = 1;
    int32_t junk_seq_offset_ = -1;
};

class DesyncHttpStrategy : public IBypassStrategy {
public:
    explicit DesyncHttpStrategy(const Config& cfg);
    BypassResult Apply(const uint8_t* original_packet, uint32_t packet_len,
                       const IPv4Header* ip, const TCPHeader* tcp,
                       std::span<const uint8_t> tcp_payload) override;
    const char* Name() const override { return "DesyncHttp"; }
};

class ChainDesyncStrategy : public IBypassStrategy {
public:
    explicit ChainDesyncStrategy(const Config& cfg);
    BypassResult Apply(const uint8_t* original_packet, uint32_t packet_len,
                       const IPv4Header* ip, const TCPHeader* tcp,
                       std::span<const uint8_t> tcp_payload) override;
    const char* Name() const override { return "ChainDesync"; }

private:
    std::vector<std::unique_ptr<IBypassStrategy>> strategies_;
};

// Factory helper
std::unique_ptr<IBypassStrategy> CreateStrategy(const Config& cfg);
