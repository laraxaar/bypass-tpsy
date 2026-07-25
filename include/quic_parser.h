/**
 * quic_parser.h — QUIC packet detector.
 *
 * WHY THIS EXISTS:
 * QUIC (HTTP/3) operates over UDP port 443. Browsers prefer QUIC over TCP
 * for performance reasons. Modern DPI blocks QUIC by sniffing QUIC Initial
 * packets containing the SNI. If QUIC is left unhandled, browser requests
 * to target hosts will fail or bypass our TCP engine.
 * This parser identifies QUIC Initial packets, enabling the main pipeline
 * to drop them. The browser then falls back to TCP, which we successfully bypass.
 */
#pragma once

#include <cstdint>
#include <span>

// Returns true if the UDP payload has a QUIC Long Header form (Header Form bit = 1, Fixed Bit = 1)
bool IsQUICLongHeader(std::span<const uint8_t> udp_payload);

// Returns true if the packet is a QUIC Initial packet (Long Header and Type matches Initial)
bool IsQUICInitial(std::span<const uint8_t> udp_payload);
