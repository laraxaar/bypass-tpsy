#include "bypass_strategy.h"
#include "tls_parser.h"
#include "logger.h"
#include <cstring>
#include <random>

// ============================================================
// Factory Helper
// ============================================================
std::unique_ptr<IBypassStrategy> CreateStrategy(const Config& cfg) {
    std::string mode = cfg.GetString("desync", "mode", "chain");
    if (mode == "split") {
        return std::make_unique<DesyncSplitStrategy>(cfg);
    } else if (mode == "junk") {
        return std::make_unique<DesyncJunkStrategy>(cfg);
    } else if (mode == "http") {
        return std::make_unique<DesyncHttpStrategy>(cfg);
    } else {
        return std::make_unique<ChainDesyncStrategy>(cfg);
    }
}

// ============================================================
// DesyncSplitStrategy
// ============================================================
DesyncSplitStrategy::DesyncSplitStrategy(const Config& cfg) {
    split_offset_ = static_cast<uint32_t>(cfg.GetInt("desync", "split_offset", 0));
    split_delay_ms_ = static_cast<uint32_t>(cfg.GetInt("desync", "split_delay_ms", 50));
}

BypassResult DesyncSplitStrategy::Apply(const uint8_t* original_packet, uint32_t packet_len,
                                        const IPv4Header* ip, const TCPHeader* tcp,
                                        std::span<const uint8_t> tcp_payload) {
    (void)packet_len;
    BypassResult res;
    if (tcp_payload.empty()) return res;

    uint32_t offset = split_offset_;
    if (offset == 0) {
        auto sni_info = FindSNIOffset(tcp_payload);
        if (sni_info) {
            offset = sni_info->first + (sni_info->second / 2);
            LOG_DEBUG2("[STRATEGY-SPLIT] Auto-calculated SNI split point", 
                "SNI Start=" + std::to_string(sni_info->first) + 
                ", SNI Length=" + std::to_string(sni_info->second) + 
                ", Split Offset=" + std::to_string(offset));
        } else {
            offset = static_cast<uint32_t>(tcp_payload.size() / 2);
            LOG_DEBUG2("[STRATEGY-SPLIT] SNI offset not found, using midpoint split", "Split Offset=" + std::to_string(offset));
        }
    }

    if (offset <= 0 || offset >= tcp_payload.size()) {
        LOG_WARN("[STRATEGY-SPLIT] Computed split offset is out of payload boundaries. Aborting split.");
        return res; 
    }

    uint32_t ip_hdr_len = ip->HeaderLength();
    uint32_t tcp_hdr_len = tcp->HeaderLength();

    // 1. Build Packet 1 [Header | Payload[0..offset]]
    uint32_t len1 = ip_hdr_len + tcp_hdr_len + offset;
    std::vector<uint8_t> data1(len1);
    std::memcpy(data1.data(), original_packet, ip_hdr_len + tcp_hdr_len);
    std::memcpy(data1.data() + ip_hdr_len + tcp_hdr_len, tcp_payload.data(), offset);

    IPv4Header* ip1 = reinterpret_cast<IPv4Header*>(data1.data());
    ip1->total_length = htons(static_cast<uint16_t>(len1));

    TCPHeader* tcp1 = reinterpret_cast<TCPHeader*>(data1.data() + ip_hdr_len);
    
    RecalcIPChecksum(ip1);
    RecalcTCPChecksum(ip1, tcp1, tcp_payload.data(), offset);

    res.packets.push_back({data1, 0}); 

    LOG_TRACE2("[STRATEGY-SPLIT-GEN] Generated segment 1", "Size=" + std::to_string(len1) + " bytes, TCP Checksum=0x" + std::to_string(ntohs(tcp1->checksum)));
    if (Logger::Get().GetLevel() <= LogLevel::Trace) {
        LOG_TRACE(Logger::HexDump(data1.data(), data1.size()));
    }

    // 2. Build Packet 2 [Header | Payload[offset..end]]
    uint32_t rem_size = static_cast<uint32_t>(tcp_payload.size() - offset);
    uint32_t len2 = ip_hdr_len + tcp_hdr_len + rem_size;
    std::vector<uint8_t> data2(len2);
    std::memcpy(data2.data(), original_packet, ip_hdr_len + tcp_hdr_len);
    std::memcpy(data2.data() + ip_hdr_len + tcp_hdr_len, tcp_payload.data() + offset, rem_size);

    IPv4Header* ip2 = reinterpret_cast<IPv4Header*>(data2.data());
    ip2->total_length = htons(static_cast<uint16_t>(len2));

    TCPHeader* tcp2 = reinterpret_cast<TCPHeader*>(data2.data() + ip_hdr_len);
    tcp2->seq_num = htonl(ntohl(tcp->seq_num) + offset);

    RecalcIPChecksum(ip2);
    RecalcTCPChecksum(ip2, tcp2, tcp_payload.data() + offset, rem_size);

    res.packets.push_back({data2, split_delay_ms_}); 

    LOG_TRACE2("[STRATEGY-SPLIT-GEN] Generated segment 2", "Size=" + std::to_string(len2) + " bytes, TCP SEQ=" + std::to_string(ntohl(tcp2->seq_num)) + ", TCP Checksum=0x" + std::to_string(ntohs(tcp2->checksum)));
    if (Logger::Get().GetLevel() <= LogLevel::Trace) {
        LOG_TRACE(Logger::HexDump(data2.data(), data2.size()));
    }

    LOG_INFO2("[STRATEGY-SPLIT-OK]", "Split complete. Split offset=" + std::to_string(offset) + ", delay=" + std::to_string(split_delay_ms_) + "ms");
    return res;
}

// ============================================================
// DesyncJunkStrategy
// ============================================================
DesyncJunkStrategy::DesyncJunkStrategy(const Config& cfg) {
    junk_size_ = static_cast<uint32_t>(cfg.GetInt("desync", "junk_size", 32));
    junk_ttl_ = static_cast<uint8_t>(cfg.GetInt("desync", "junk_ttl", 1));
    junk_seq_offset_ = static_cast<int32_t>(cfg.GetInt("desync", "junk_seq_offset", -1));
}

BypassResult DesyncJunkStrategy::Apply(const uint8_t* original_packet, uint32_t packet_len,
                                       const IPv4Header* ip, const TCPHeader* tcp,
                                       std::span<const uint8_t> tcp_payload) {
    BypassResult res;
    if (tcp_payload.empty()) return res;

    uint32_t ip_hdr_len = ip->HeaderLength();
    uint32_t tcp_hdr_len = tcp->HeaderLength();

    // 1. Build Junk Packet [Headers | Random bytes]
    uint32_t junk_packet_len = ip_hdr_len + tcp_hdr_len + junk_size_;
    std::vector<uint8_t> junk_data(junk_packet_len);
    
    std::memcpy(junk_data.data(), original_packet, ip_hdr_len + tcp_hdr_len);

    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (uint32_t i = 0; i < junk_size_; ++i) {
        junk_data[ip_hdr_len + tcp_hdr_len + i] = static_cast<uint8_t>(dis(gen));
    }

    IPv4Header* junk_ip = reinterpret_cast<IPv4Header*>(junk_data.data());
    junk_ip->ttl = junk_ttl_;
    junk_ip->total_length = htons(static_cast<uint16_t>(junk_packet_len));

    TCPHeader* junk_tcp = reinterpret_cast<TCPHeader*>(junk_data.data() + ip_hdr_len);
    uint32_t real_seq = ntohl(tcp->seq_num);
    uint32_t junk_seq = real_seq + junk_seq_offset_;
    junk_tcp->seq_num = htonl(junk_seq);
    junk_tcp->flags = TcpFlags::PSH | TcpFlags::ACK;

    RecalcIPChecksum(junk_ip);
    RecalcTCPChecksum(junk_ip, junk_tcp, junk_data.data() + ip_hdr_len + tcp_hdr_len, junk_size_);

    res.packets.push_back({junk_data, 0}); 

    LOG_TRACE2("[STRATEGY-JUNK-GEN] Generated out-of-window junk packet", 
        "Size=" + std::to_string(junk_packet_len) + " bytes, TTL=" + std::to_string(junk_ttl_) + 
        ", SEQ=" + std::to_string(junk_seq) + " (offset " + std::to_string(junk_seq_offset_) + ")");
    
    if (Logger::Get().GetLevel() <= LogLevel::Trace) {
        LOG_TRACE(Logger::HexDump(junk_data.data(), junk_data.size()));
    }

    // 2. Real unmodified packet follows immediately
    std::vector<uint8_t> real_data(original_packet, original_packet + packet_len);
    res.packets.push_back({real_data, 0});

    LOG_INFO2("[STRATEGY-JUNK-OK]", "Junk packet injected successfully");
    return res;
}

// ============================================================
// DesyncHttpStrategy
// ============================================================
DesyncHttpStrategy::DesyncHttpStrategy(const Config& /*cfg*/) {}

BypassResult DesyncHttpStrategy::Apply(const uint8_t* original_packet, uint32_t packet_len,
                                       const IPv4Header* ip, const TCPHeader* tcp,
                                       std::span<const uint8_t> tcp_payload) {
    (void)packet_len;
    BypassResult res;
    if (tcp_payload.empty()) return res;

    if (ntohs(tcp->dst_port) != 80) return res;

    std::string http_data(reinterpret_cast<const char*>(tcp_payload.data()), tcp_payload.size());
    size_t space = http_data.find(' ');
    if (space == std::string::npos || space > 10) return res; 

    std::string modified_http = http_data.substr(0, space) + "  " + http_data.substr(space + 1);

    uint32_t ip_hdr_len = ip->HeaderLength();
    uint32_t tcp_hdr_len = tcp->HeaderLength();
    uint32_t new_len = ip_hdr_len + tcp_hdr_len + (uint32_t)modified_http.size();

    std::vector<uint8_t> data(new_len);
    std::memcpy(data.data(), original_packet, ip_hdr_len + tcp_hdr_len);
    std::memcpy(data.data() + ip_hdr_len + tcp_hdr_len, modified_http.data(), modified_http.size());

    IPv4Header* new_ip = reinterpret_cast<IPv4Header*>(data.data());
    new_ip->total_length = htons(static_cast<uint16_t>(new_len));

    TCPHeader* new_tcp = reinterpret_cast<TCPHeader*>(data.data() + ip_hdr_len);

    RecalcIPChecksum(new_ip);
    RecalcTCPChecksum(new_ip, new_tcp, reinterpret_cast<const uint8_t*>(modified_http.data()), (uint32_t)modified_http.size());

    res.packets.push_back({data, 0});
    LOG_INFO("[STRATEGY-HTTP-OK] Applied HTTP space smuggling desynchronization.");
    
    if (Logger::Get().GetLevel() <= LogLevel::Trace) {
        LOG_TRACE(Logger::HexDump(data.data(), data.size()));
    }
    
    return res;
}

// ============================================================
// ChainDesyncStrategy
// ============================================================
ChainDesyncStrategy::ChainDesyncStrategy(const Config& cfg) {
    std::vector<std::string> order = cfg.GetStringList("desync", "chain_order");
    if (order.empty()) {
        order = {"junk", "split"}; 
    }

    for (const auto& name : order) {
        if (name == "junk") {
            strategies_.push_back(std::make_unique<DesyncJunkStrategy>(cfg));
        } else if (name == "split") {
            strategies_.push_back(std::make_unique<DesyncSplitStrategy>(cfg));
        } else if (name == "http") {
            strategies_.push_back(std::make_unique<DesyncHttpStrategy>(cfg));
        }
    }
    LOG_DEBUG2("[STRATEGY-CHAIN] Initialized chain pipeline. Size", std::to_string(strategies_.size()));
}

BypassResult ChainDesyncStrategy::Apply(const uint8_t* original_packet, uint32_t packet_len,
                                        const IPv4Header* ip, const TCPHeader* tcp,
                                        std::span<const uint8_t> tcp_payload) {
    (void)ip;
    (void)tcp;
    (void)tcp_payload;
    BypassResult current_res;
    
    PacketToSend seed;
    seed.data.assign(original_packet, original_packet + packet_len);
    seed.delay_ms = 0;
    current_res.packets.push_back(seed);

    LOG_TRACE2("[STRATEGY-CHAIN] Executing chain pipeline", "Input size=" + std::to_string(packet_len) + " bytes");

    for (size_t i = 0; i < strategies_.size(); ++i) {
        const auto& strat = strategies_[i];
        if (current_res.packets.empty()) break;

        PacketToSend target = current_res.packets.back();
        current_res.packets.pop_back();

        auto* target_ip = ParseIPv4(target.data.data(), (uint32_t)target.data.size());
        if (!target_ip) continue;
        auto* target_tcp = ParseTCP(target_ip, (uint32_t)target.data.size());
        if (!target_tcp) continue;
        auto target_payload = GetTCPPayload(target_ip, target_tcp, (uint32_t)target.data.size());

        LOG_TRACE2("[STRATEGY-CHAIN] Calling sub-strategy " + std::to_string(i + 1) + "/" + std::to_string(strategies_.size()), strat->Name());

        BypassResult strat_res = strat->Apply(target.data.data(), (uint32_t)target.data.size(), target_ip, target_tcp, target_payload);
        if (strat_res.packets.empty()) {
            LOG_TRACE2("[STRATEGY-CHAIN] Sub-strategy skipped. Restoring input target", strat->Name());
            current_res.packets.push_back(target);
        } else {
            for (auto& p : strat_res.packets) {
                p.delay_ms += target.delay_ms;
                current_res.packets.push_back(p);
            }
        }
    }

    LOG_DEBUG2("[STRATEGY-CHAIN-OK] Chain pipeline execution completed", "Generated " + std::to_string(current_res.packets.size()) + " packets");
    return current_res;
}
