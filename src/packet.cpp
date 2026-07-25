#include "packet.h"
#include <cstring>
#include <vector>

// ============================================================
// Parsing
// ============================================================

const IPv4Header* ParseIPv4(const uint8_t* data, uint32_t len) {
    if (!data || len < sizeof(IPv4Header)) return nullptr;

    auto* ip = reinterpret_cast<const IPv4Header*>(data);
    if (ip->version != 4) return nullptr;
    if (ip->HeaderLength() < 20) return nullptr;  // Minimum IPv4 header
    if (ip->HeaderLength() > len) return nullptr;

    uint32_t total = ntohs(ip->total_length);
    if (total < ip->HeaderLength() || total > len) return nullptr;

    return ip;
}

const TCPHeader* ParseTCP(const IPv4Header* ip, uint32_t total_packet_len) {
    if (!ip || ip->protocol != 6) return nullptr;

    uint32_t ip_hdr_len = ip->HeaderLength();
    const uint8_t* ip_raw = reinterpret_cast<const uint8_t*>(ip);

    if (ip_hdr_len + sizeof(TCPHeader) > total_packet_len) return nullptr;

    auto* tcp = reinterpret_cast<const TCPHeader*>(ip_raw + ip_hdr_len);
    if (tcp->HeaderLength() < 20) return nullptr;
    if (ip_hdr_len + tcp->HeaderLength() > total_packet_len) return nullptr;

    return tcp;
}

const UDPHeader* ParseUDP(const IPv4Header* ip, uint32_t total_packet_len) {
    if (!ip || ip->protocol != 17) return nullptr;

    uint32_t ip_hdr_len = ip->HeaderLength();
    const uint8_t* ip_raw = reinterpret_cast<const uint8_t*>(ip);

    if (ip_hdr_len + sizeof(UDPHeader) > total_packet_len) return nullptr;

    auto* udp = reinterpret_cast<const UDPHeader*>(ip_raw + ip_hdr_len);

    uint32_t udp_len = ntohs(udp->length);
    if (udp_len < sizeof(UDPHeader)) return nullptr;
    if (ip_hdr_len + udp_len > total_packet_len) return nullptr;

    return udp;
}

std::span<const uint8_t> GetTCPPayload(const IPv4Header* ip, const TCPHeader* tcp,
                                        uint32_t total_packet_len) {
    if (!ip || !tcp) return {};

    uint32_t ip_total = ntohs(ip->total_length);
    uint32_t headers = ip->HeaderLength() + tcp->HeaderLength();
    if (headers >= ip_total) return {};

    const uint8_t* base = reinterpret_cast<const uint8_t*>(ip);
    uint32_t payload_len = ip_total - headers;

    // Safety check against buffer
    if (headers + payload_len > total_packet_len) return {};

    return { base + headers, payload_len };
}

std::span<const uint8_t> GetUDPPayload(const IPv4Header* ip, const UDPHeader* udp,
                                        uint32_t total_packet_len) {
    if (!ip || !udp) return {};

    uint32_t ip_hdr_len = ip->HeaderLength();
    uint32_t udp_len = ntohs(udp->length);
    if (udp_len <= sizeof(UDPHeader)) return {};

    uint32_t payload_len = udp_len - sizeof(UDPHeader);
    uint32_t offset = ip_hdr_len + sizeof(UDPHeader);

    if (offset + payload_len > total_packet_len) return {};

    const uint8_t* base = reinterpret_cast<const uint8_t*>(ip);
    return { base + offset, payload_len };
}

// ============================================================
// Checksums
// ============================================================

// RFC 1071 checksum: ones-complement sum of 16-bit words
static uint16_t ComputeChecksum(const uint8_t* data, uint32_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        uint16_t word;
        std::memcpy(&word, data, 2);
        sum += word;
        data += 2;
        len -= 2;
    }
    if (len == 1) {
        uint16_t word = 0;
        std::memcpy(&word, data, 1);
        sum += word;
    }
    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

void RecalcIPChecksum(IPv4Header* ip) {
    ip->checksum = 0;
    ip->checksum = ComputeChecksum(reinterpret_cast<uint8_t*>(ip), ip->HeaderLength());
}

void RecalcTCPChecksum(IPv4Header* ip, TCPHeader* tcp,
                       const uint8_t* payload, uint32_t payload_len) {
    tcp->checksum = 0;

    uint32_t tcp_hdr_len = tcp->HeaderLength();
    uint32_t tcp_total = tcp_hdr_len + payload_len;

    // Build pseudo-header + TCP header + payload for checksum computation
    // Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + proto(1) + tcp_length(2) = 12 bytes
    uint32_t buf_len = 12 + tcp_total;
    std::vector<uint8_t> buf(buf_len, 0);

    // Pseudo-header
    std::memcpy(&buf[0], &ip->src_addr, 4);
    std::memcpy(&buf[4], &ip->dst_addr, 4);
    buf[8] = 0;
    buf[9] = 6;  // IPPROTO_TCP
    uint16_t tcp_len_net = htons(static_cast<uint16_t>(tcp_total));
    std::memcpy(&buf[10], &tcp_len_net, 2);

    // TCP header
    std::memcpy(&buf[12], tcp, tcp_hdr_len);

    // TCP payload
    if (payload && payload_len > 0) {
        std::memcpy(&buf[12 + tcp_hdr_len], payload, payload_len);
    }

    tcp->checksum = ComputeChecksum(buf.data(), buf_len);
}
