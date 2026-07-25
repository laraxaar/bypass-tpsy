#include "quic_parser.h"

bool IsQUICLongHeader(std::span<const uint8_t> udp_payload) {
    if (udp_payload.size() < 5) return false;
    uint8_t first_byte = udp_payload[0];
    
    // Header Form bit is 0x80 (1 = Long Header)
    // Fixed Bit is 0x40 (Must be 1 in QUIC v1/v2, though draft variations exist)
    return (first_byte & 0x80) && (first_byte & 0x40);
}

bool IsQUICInitial(std::span<const uint8_t> udp_payload) {
    if (!IsQUICLongHeader(udp_payload)) return false;

    uint8_t first_byte = udp_payload[0];

    // Packet Type in Long Header is represented by bits 4 and 5 of the first byte.
    // 00 = Initial
    // 01 = 0-RTT
    // 10 = Handshake
    // 11 = Retry
    // First byte structure (QUIC v1):
    // Header Form (1 bit) | Fixed Bit (1 bit) | Long Packet Type (2 bits) | Type-Specific Bits (4 bits)
    uint8_t type = (first_byte & 0x30) >> 4;

    if (type != 0x00) return false;

    // Verify QUIC Version (bytes 1-4) is not 0x00000000 (which would be Version Negotiation)
    uint32_t version = (udp_payload[1] << 24) | (udp_payload[2] << 16) | (udp_payload[3] << 8) | udp_payload[4];
    if (version == 0) return false; // Version Negotiation packet

    return true;
}
