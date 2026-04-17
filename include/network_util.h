#pragma once
#include <winsock2.h>
#include <stdint.h>

// IPv4 Header
struct IPHeader {
    uint8_t  h_len : 4;         // Header length
    uint8_t  version : 4;       // IP version
    uint8_t  tos;               // Type of service
    uint16_t total_len;         // Total length
    uint16_t ident;             // Identifier
    uint16_t frag_and_flags;    // Fragments and flags
    uint8_t  ttl;               // Time to live
    uint8_t  proto;             // Protocol (6=TCP, 17=UDP)
    uint16_t checksum;          // Checksum
    uint32_t source_ip;         // Source IP
    uint32_t dest_ip;           // Destination IP
};

// TCP Header
struct TCPHeader {
    uint16_t source_port;       // Source port
    uint16_t dest_port;         // Destination port
    uint32_t seq;               // Sequence number
    uint32_t ack;               // Acknowledgment number
    uint8_t  res1 : 4;          // Reserved
    uint8_t  doff : 4;          // Data offset
    uint8_t  flags;             // TCP flags
    uint16_t window;            // Window size
    uint16_t checksum;          // Checksum
    uint16_t urgent_ptr;        // Urgent pointer
};

// TLS Record Header
struct TLSRecordHeader {
    uint8_t  type;              // 0x16 = Handshake
    uint16_t version;           // TLS Version
    uint16_t length;            // Payload length
};

// Utils
inline uint16_t SwapBytes16(uint16_t val) {
    return (val << 8) | (val >> 8);
}

inline uint32_t SwapBytes32(uint32_t val) {
    return ((val & 0xff000000) >> 24) | ((val & 0x00ff0000) >> 8) |
           ((val & 0x0000ff00) << 8)  | ((val & 0x000000ff) << 24);
}
