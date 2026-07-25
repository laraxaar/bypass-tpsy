/**
 * tunnel_io.h — Wintun TUN adapter interface.
 *
 * WHY THIS EXISTS:
 * The original wintun_manager.cpp was a dummy implementation: it initialized
 * the adapter but never read any packets from it. The configuration of IP/routes
 * was completely missing.
 * This class provides a robust RAII wrapper around Wintun. It:
 * 1. Dynamically loads wintun.dll from the system.
 * 2. Creates or opens the specified TUN adapter.
 * 3. Configures IP and subnets on the adapter using the IP Helper API.
 * 4. Starts the read session ring buffer.
 * 5. Provides thread-safe packet reading.
 */
#pragma once

// КРИТИЧЕСКИ ВАЖНО: Определяем версию Windows ДО всех include'ов
// Нужно для SetIfEntry2, InterfaceMetric, AdministrativeState и прочих полей
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601  // Windows 7 (минимум для нужных сетевых функций)
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Чтобы избежать warning'ов C4005 о переопределении STATUS_* макросов
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif

// 1. Сначала подгружаем базовый сетевой стек и типы Windows
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// 2. Теперь безопасно подключаем API управления сетевыми интерфейсами
#include <netioapi.h>

#include <string>
#include <optional>
#include "config.h"

// Wintun types to avoid header namespace collisions
typedef struct _WINTUN_ADAPTER *WINTUN_ADAPTER_HANDLE;
typedef struct _WINTUN_SESSION *WINTUN_SESSION_HANDLE;

class TunnelIO {
public:
    struct Packet {
        const uint8_t* data;
        uint32_t size;
    };

    explicit TunnelIO(const Config& cfg);
    ~TunnelIO();

    // Block or timeout waiting for a packet from Wintun
    std::optional<Packet> Receive(uint32_t timeout_ms = 100);

    // Releases a received packet back to Wintun ring buffer
    void Release(const Packet& packet);

    // Injects a raw packet inbound back to the local OS network stack
    bool Send(const uint8_t* data, uint32_t len);

    // Get information about the TUN interface
    NET_LUID GetAdapterLuid() const { return luid_; }
    // ИСПРАВЛЕНО: NET_IFINDEX вместо uint32_t для совместимости с ConvertInterfaceLuidToIndex
    NET_IFINDEX GetAdapterIndex() const { return index_; }

    // Disable copy
    TunnelIO(const TunnelIO&) = delete;
    TunnelIO& operator=(const TunnelIO&) = delete;

private:
    HMODULE wintun_dll_ = nullptr;
    WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
    WINTUN_SESSION_HANDLE session_ = nullptr;
    HANDLE read_event_ = nullptr;
    NET_LUID luid_{0};
    NET_IFINDEX index_ = 0;  // ИСПРАВЛЕНО: был uint32_t, стал NET_IFINDEX (ULONG)

    // Dynamically loaded function pointers
    typedef WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(const wchar_t*, const wchar_t*, const GUID*);
    typedef WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_OPEN_ADAPTER_FUNC)(const wchar_t*);
    typedef void(WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE);
    typedef BOOL(WINAPI *WINTUN_GET_ADAPTER_LUID_FUNC)(WINTUN_ADAPTER_HANDLE, NET_LUID*);
    typedef WINTUN_SESSION_HANDLE(WINAPI *WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE, uint32_t);
    typedef void(WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE);
    typedef HANDLE(WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE);
    typedef uint8_t*(WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, uint32_t*);
    typedef void(WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, const uint8_t*);
    
    // ДОБАВЛЕНО: Недостающие типы функций для отправки пакетов в Wintun
    typedef uint8_t*(WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, uint32_t);
    typedef void(WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, const uint8_t*);

    WINTUN_CREATE_ADAPTER_FUNC CreateAdapter = nullptr;
    WINTUN_OPEN_ADAPTER_FUNC OpenAdapter = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC CloseAdapter = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC GetAdapterLuidFunc = nullptr; // Избегаем C2365
    WINTUN_START_SESSION_FUNC StartSession = nullptr;
    WINTUN_END_SESSION_FUNC EndSession = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC GetReadWaitEvent = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC ReceivePacket = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC ReleaseReceivePacket = nullptr;
    
    // ДОБАВЛЕНО: Указатели на функции отправки
    WINTUN_ALLOCATE_SEND_PACKET_FUNC AllocateSendPacket = nullptr;
    WINTUN_SEND_PACKET_FUNC SendPacket = nullptr;

    bool LoadWintun();
    bool ConfigureInterface(const std::string& ip_str, const std::string& mask_str);
};