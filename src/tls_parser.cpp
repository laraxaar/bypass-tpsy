#include "tls_parser.h"
#include <cstring>

bool IsTLSHandshake(std::span<const uint8_t> payload) {
    if (payload.size() < 5) return false;
    return payload[0] == 0x16; // Record type 22 (Handshake)
}

bool IsClientHello(std::span<const uint8_t> payload) {
    if (!IsTLSHandshake(payload) || payload.size() < 6) return false;
    // Record version is bytes 1-2. Record length is bytes 3-4.
    // Handshake protocol starts at byte 5. Handshake type 1 is ClientHello.
    return payload[5] == 0x01;
}

std::optional<std::pair<uint32_t, uint32_t>> FindSNIOffset(std::span<const uint8_t> payload) {
    if (!IsClientHello(payload)) return std::nullopt;

    size_t size = payload.size();
    if (size < 43) return std::nullopt; // Minimum ClientHello length up to Session ID length

    size_t cursor = 5; // Start of Handshake Layer

    // Skip Handshake Type (1) and Length (3)
    cursor += 4;

    // Skip Version (2) + Random (32)
    cursor += 34;

    if (cursor >= size) return std::nullopt;

    // Session ID length
    uint8_t session_id_len = payload[cursor];
    cursor += 1 + session_id_len;

    if (cursor + 2 > size) return std::nullopt;

    // Cipher Suites length
    uint16_t cipher_suites_len = (payload[cursor] << 8) | payload[cursor + 1];
    cursor += 2 + cipher_suites_len;

    if (cursor + 1 > size) return std::nullopt;

    // Compression Methods length
    uint8_t compression_len = payload[cursor];
    cursor += 1 + compression_len;

    if (cursor + 2 > size) return std::nullopt;

    // Extensions length
    uint16_t extensions_len = (payload[cursor] << 8) | payload[cursor + 1];
    cursor += 2;

    size_t extensions_end = cursor + extensions_len;
    if (extensions_end > size) return std::nullopt;

    // Iterate extensions to find Server Name Indication (SNI) (0x0000)
    while (cursor + 4 <= extensions_end) {
        uint16_t ext_type = (payload[cursor] << 8) | payload[cursor + 1];
        uint16_t ext_len = (payload[cursor + 2] << 8) | payload[cursor + 3];
        cursor += 4;

        if (cursor + ext_len > extensions_end) return std::nullopt;

        if (ext_type == 0x0000) {
            // SNI Extension found.
            // SNI payload:
            //   - List length (2 bytes)
            //   - Server name type (1 byte, 0 = host_name)
            //   - Server name length (2 bytes)
            //   - Server name value (var bytes)
            size_t sni_cursor = cursor;
            if (sni_cursor + 5 > cursor + ext_len) return std::nullopt;

            sni_cursor += 2;

            if (sni_cursor + 3 > cursor + ext_len) return std::nullopt;

            uint8_t name_type = payload[sni_cursor];
            sni_cursor += 1;

            if (name_type == 0x00) { // host_name
                uint16_t name_len = (payload[sni_cursor] << 8) | payload[sni_cursor + 1];
                sni_cursor += 2;

                if (sni_cursor + name_len > cursor + ext_len) return std::nullopt;

                return std::make_pair(static_cast<uint32_t>(sni_cursor), static_cast<uint32_t>(name_len));
            }
        }
        cursor += ext_len;
    }

    return std::nullopt;
}

std::optional<std::string> ExtractSNI(std::span<const uint8_t> payload) {
    auto offset_info = FindSNIOffset(payload);
    if (!offset_info) return std::nullopt;

    uint32_t offset = offset_info->first;
    uint32_t len = offset_info->second;

    return std::string(reinterpret_cast<const char*>(payload.data() + offset), len);
}
