/**
 * tls_parser.h — TLS ClientHello SNI parser.
 *
 * WHY THIS EXISTS:
 * Unlike the original codebase which did not parse the structure of the ClientHello,
 * this module parses TLS records securely. It identifies if the payload is a ClientHello,
 * extracts the SNI (Server Name Indication), and calculates the byte offsets of the SNI string.
 * This is crucial for splitting strategies (DesyncSplit) to split *precisely* within the SNI payload.
 * It is fully self-contained with no external dependencies (e.g. OpenSSL).
 */
#pragma once

#include <string>
#include <optional>
#include <span>

// Check if packet starts with standard TLS Handshake record type (0x16)
bool IsTLSHandshake(std::span<const uint8_t> payload);

// Check if Handshake Type is Client Hello (0x01)
bool IsClientHello(std::span<const uint8_t> payload);

// Extract SNI string from ClientHello
std::optional<std::string> ExtractSNI(std::span<const uint8_t> payload);

// Find the offset and size of the SNI hostname inside the TCP payload.
// Returns {offset_from_payload_start, hostname_length} or nullopt.
std::optional<std::pair<uint32_t, uint32_t>> FindSNIOffset(std::span<const uint8_t> payload);
