/**
 * packet.h — IP/TCP/UDP header structures and parsing.
 *
 * WHY THIS EXISTS:
 * The original network_util.h had:
 *   - Wrong bit-field order for MSVC (h_len before version — MSVC packs
 *     bit-fields LSB-first within a byte, so on LE machines this is correct
 *     only if the nibble order matches the wire order).
 *   - No UDP header (QUIC needs it).
 *   - Custom byte-swap macros instead of ntohs/ntohl.
 *   - No parsing functions — headers were cast from raw pointers without
 *     bounds checking.
 *
 * This module provides safe parsing that validates lengths before
 * returning pointers, and uses ntohs/ntohl for all multi-byte fields.
 */
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <cstdint>
#include <span>

// ============================================================
// Header structures — fields in network byte order on the wire.
// Use ntohs()/ntohl() when reading multi-byte fields.
// ============================================================

#pragma pack(push, 1)

struct IPv4Header {
    // On MSVC/LE: bit-fields within a byte are packed LSB-first.
    // Wire byte 0: version (high nibble) | ihl (low nibble).
    // With LSB-first packing, ihl occupies bits 0-3, version bits 4-7.
    uint8_t  ihl     : 4;   // Internet Header Length (in 32-bit words)
    uint8_t  version : 4;   // IP version (4)
    uint8_t  tos;            // Type of Service / DSCP+ECN
    uint16_t total_length;   // Total packet length (network order)
    uint16_t identification; // Fragment identification
    uint16_t flags_fragment;  // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t  ttl;            // Time To Live
    uint8_t  protocol;       // 6=TCP, 17=UDP
    uint16_t checksum;       // Header checksum
    uint32_t src_addr;       // Source IP (network order)
    uint32_t dst_addr;       // Destination IP (network order)
    // Options may follow (if ihl > 5)

    uint32_t HeaderLength() const { return static_cast<uint32_t>(ihl) * 4; }
};

struct TCPHeader {
    uint16_t src_port;   // Source port (network order)
    uint16_t dst_port;   // Destination port (network order)
    uint32_t seq_num;    // Sequence number (network order)
    uint32_t ack_num;    // Acknowledgment number (network order)
    // On MSVC/LE: data_offset occupies high nibble of byte 12, reserved the low.
    uint8_t  reserved : 4;
    uint8_t  data_offset : 4;  // Header length in 32-bit words
    uint8_t  flags;      // TCP flags (FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10)
    uint16_t window;     // Window size (network order)
    uint16_t checksum;   // Checksum (network order)
    uint16_t urgent_ptr; // Urgent pointer (network order)
    // Options may follow (if data_offset > 5)

    uint32_t HeaderLength() const { return static_cast<uint32_t>(data_offset) * 4; }
};

struct UDPHeader {
    uint16_t src_port;   // Source port (network order)
    uint16_t dst_port;   // Destination port (network order)
    uint16_t length;     // UDP length (header + data, network order)
    uint16_t checksum;   // Checksum (network order)
};

#pragma pack(pop)

// TCP flag constants
namespace TcpFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

// ============================================================
// Parsing functions — return nullptr/empty span on malformed input
// ============================================================

// Parse IPv4 header from raw packet. Returns nullptr if too short or not IPv4.
const IPv4Header* ParseIPv4(const uint8_t* data, uint32_t len);

// Parse TCP header from a validated IPv4 packet. Returns nullptr if too short or not TCP.
const TCPHeader* ParseTCP(const IPv4Header* ip, uint32_t total_packet_len);

// Parse UDP header from a validated IPv4 packet. Returns nullptr if too short or not UDP.
const UDPHeader* ParseUDP(const IPv4Header* ip, uint32_t total_packet_len);

// Extract TCP payload (data after TCP header, before end of IP packet).
std::span<const uint8_t> GetTCPPayload(const IPv4Header* ip, const TCPHeader* tcp,
                                        uint32_t total_packet_len);

// Extract UDP payload (data after UDP header).
std::span<const uint8_t> GetUDPPayload(const IPv4Header* ip, const UDPHeader* udp,
                                        uint32_t total_packet_len);

// ============================================================
// Checksum functions
// ============================================================

// Recalculate IPv4 header checksum in-place.
void RecalcIPChecksum(IPv4Header* ip);

// Recalculate TCP checksum in-place (requires pseudo-header from IP).
void RecalcTCPChecksum(IPv4Header* ip, TCPHeader* tcp,
                       const uint8_t* payload, uint32_t payload_len);
