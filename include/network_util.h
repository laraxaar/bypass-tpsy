#pragma once
#include <winsock2.h>
#include <stdint.h>

// IPv4 Header
struct IPHeader {
    uint8_t  h_len : 4;         // Длина заголовка
    uint8_t  version : 4;       // Версия
    uint8_t  tos;               // Type of service
    uint16_t total_len;         // Общая длина
    uint16_t ident;             // Идентификатор
    uint16_t frag_and_flags;    // Флаги и смещение фрагмента
    uint8_t  ttl;               // Time to live
    uint8_t  proto;             // Протокол
    uint16_t checksum;          // Контрольная сумма
    uint32_t source_ip;         // IP отправителя
    uint32_t dest_ip;           // IP получателя
};

// TCP Header
struct TCPHeader {
    uint16_t source_port;       // Порт отправителя
    uint16_t dest_port;         // Порт получателя
    uint32_t seq;               // Sequence number
    uint32_t ack;               // Acknowledgment number
    uint8_t  res1 : 4;          // Зарезервировано
    uint8_t  doff : 4;          // Data offset
    uint8_t  flags;             // Флаги (FIN, SYN, RST, PSH, ACK, URG)
    uint16_t window;            // Размер окна
    uint16_t checksum;          // Контрольная сумма
    uint16_t urgent_ptr;        // Urgent pointer
};

// TLS Record Header
struct TLSRecordHeader {
    uint8_t  type;              // Content Type (22 = Handshake)
    uint16_t version;           // TLS Version
    uint16_t length;            // Длина записи
};

// TLS Handshake Header
struct TLSHandshakeHeader {
    uint8_t  type;              // Handshake Type (1 = Client Hello)
    uint8_t  length[3];         // Длина сообщения
};

// Утилиты
inline uint16_t SwapBytes16(uint16_t val) {
    return (val << 8) | (val >> 8);
}

inline uint32_t SwapBytes32(uint32_t val) {
    return ((val & 0xff000000) >> 24) | ((val & 0x00ff0000) >> 8) |
           ((val & 0x0000ff00) << 8)  | ((val & 0x000000ff) << 24);
}
