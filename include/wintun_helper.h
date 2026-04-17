#pragma once
#include <windows.h>
#include <stdint.h>

// Типы данных WinTun
typedef struct _WINTUN_ADAPTER *WINTUN_ADAPTER_HANDLE;
typedef struct _WINTUN_SESSION *WINTUN_SESSION_HANDLE;

typedef enum {
    WINTUN_LOGGER_INFO,
    WINTUN_LOGGER_WARN,
    WINTUN_LOGGER_ERR
} WINTUN_LOGGER_LEVEL;

typedef void(*WINTUN_LOGGER_CALLBACK)(WINTUN_LOGGER_LEVEL Level, uint64_t Timestamp, const wchar_t *Message);

// Прототипы функций
typedef WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(const wchar_t *Name, const wchar_t *TunnelType, const GUID *RequestedGuid);
typedef WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_OPEN_ADAPTER_FUNC)(const wchar_t *Name);
typedef void(WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE Adapter);
typedef BOOL(WINAPI *WINTUN_GET_ADAPTER_LUID_FUNC)(WINTUN_ADAPTER_HANDLE Adapter, NET_LUID *Luid);
typedef WINTUN_SESSION_HANDLE(WINAPI *WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE Adapter, uint32_t Capacity);
typedef void(WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef HANDLE(WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef uint8_t *(WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, uint32_t *PacketSize);
typedef void(WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, const uint8_t *Packet);
typedef uint8_t *(WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, uint32_t PacketSize);
typedef void(WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, const uint8_t *Packet);

struct WintunAPI {
    HMODULE Module;
    WINTUN_CREATE_ADAPTER_FUNC CreateAdapter;
    WINTUN_OPEN_ADAPTER_FUNC OpenAdapter;
    WINTUN_CLOSE_ADAPTER_FUNC CloseAdapter;
    WINTUN_GET_ADAPTER_LUID_FUNC GetAdapterLuid;
    WINTUN_START_SESSION_FUNC StartSession;
    WINTUN_END_SESSION_FUNC EndSession;
    WINTUN_GET_READ_WAIT_EVENT_FUNC GetReadWaitEvent;
    WINTUN_RECEIVE_PACKET_FUNC ReceivePacket;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC ReleaseReceivePacket;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC AllocateSendPacket;
    WINTUN_SEND_PACKET_FUNC SendPacket;

    bool Load() {
        Module = LoadLibraryW(L"wintun.dll");
        if (!Module) return false;

        CreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(Module, "WintunCreateAdapter");
        OpenAdapter = (WINTUN_OPEN_ADAPTER_FUNC)GetProcAddress(Module, "WintunOpenAdapter");
        CloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC)GetProcAddress(Module, "WintunCloseAdapter");
        GetAdapterLuid = (WINTUN_GET_ADAPTER_LUID_FUNC)GetProcAddress(Module, "WintunGetAdapterLuid");
        StartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(Module, "WintunStartSession");
        EndSession = (WINTUN_END_SESSION_FUNC)GetProcAddress(Module, "WintunEndSession");
        GetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC)GetProcAddress(Module, "WintunGetReadWaitEvent");
        ReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(Module, "WintunReceivePacket");
        ReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC)GetProcAddress(Module, "WintunReleaseReceivePacket");
        AllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC)GetProcAddress(Module, "WintunAllocateSendPacket");
        SendPacket = (WINTUN_SEND_PACKET_FUNC)GetProcAddress(Module, "WintunSendPacket");

        return CreateAdapter && StartSession && ReceivePacket && SendPacket;
    }

    void Unload() {
        if (Module) FreeLibrary(Module);
    }
};
