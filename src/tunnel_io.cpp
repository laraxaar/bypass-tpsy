// ОБЯЗАТЕЛЬНО ПЕРВЫМ: определяем версию Windows для сетевых функций
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Windows 7 (минимум для сетевых функций IP Helper)
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif

// Теперь можно включать сетевые заголовки
#include <iphlpapi.h>
#include <netioapi.h>
#include <ntstatus.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// Локальные инклуды проекта
#include "logger.h"
#include "tunnel_io.h"
#include <cstring>
#include <stdexcept>

#pragma comment(lib, "iphlpapi.lib")

TunnelIO::TunnelIO(const Config &cfg) {
  if (!LoadWintun()) {
    throw std::runtime_error("Failed to load Wintun DLL");
  }

  std::string adapter_name_str =
      cfg.GetString("tunnel", "adapter_name", "BypassTUN");
  std::wstring adapter_name(adapter_name_str.begin(), adapter_name_str.end());

  // Generate/Use a GUID for the adapter
  GUID guid = {0x5a17e082,
               0x12c4,
               0x48bb,
               {0x93, 0x47, 0x22, 0xb1, 0x6e, 0xfa, 0x2a, 0x5c}};

  LOG_INFO2("Opening/Creating Wintun adapter", adapter_name_str);

  // Attempt open first, then fallback to create
  adapter_ = OpenAdapter(adapter_name.c_str());
  if (!adapter_) {
    adapter_ = CreateAdapter(adapter_name.c_str(), L"BypassTunnel", &guid);
  }

  if (!adapter_) {
    throw std::runtime_error("Failed to create/open Wintun adapter");
  }

  // Использован корректный указатель GetAdapterLuidFunc вместо конфликтующего
  // имени метода класса
  if (!GetAdapterLuidFunc(adapter_, &luid_)) {
    CloseAdapter(adapter_);
    adapter_ = nullptr;
    throw std::runtime_error("Failed to get Wintun LUID");
  }

  // [ИСПРАВЛЕНО] Используем NET_IFINDEX вместо uint32_t для
  // ConvertInterfaceLuidToIndex
  NET_IFINDEX index_temp;
  if (ConvertInterfaceLuidToIndex(&luid_, &index_temp) != NO_ERROR) {
    CloseAdapter(adapter_);
    adapter_ = nullptr;
    throw std::runtime_error("Failed to convert interface LUID to Index");
  }
  index_ = static_cast<uint32_t>(index_temp);

  std::string ip_str = cfg.GetString("tunnel", "adapter_ip", "10.127.0.1");
  std::string mask_str =
      cfg.GetString("tunnel", "adapter_mask", "255.255.255.0");
  if (!ConfigureInterface(ip_str, mask_str)) {
    CloseAdapter(adapter_);
    adapter_ = nullptr;
    throw std::runtime_error("Failed to configure Wintun IP address");
  }

  uint32_t capacity =
      cfg.GetInt("tunnel", "session_capacity", 0x400000); // 4MB default
  session_ = StartSession(adapter_, capacity);
  if (!session_) {
    CloseAdapter(adapter_);
    adapter_ = nullptr;
    throw std::runtime_error("Failed to start Wintun session");
  }

  read_event_ = GetReadWaitEvent(session_);
  LOG_INFO2("Wintun tunnel successfully opened",
            adapter_name_str + " (" + ip_str + ")");
}

TunnelIO::~TunnelIO() {
  if (session_) {
    EndSession(session_);
  }
  if (adapter_) {
    CloseAdapter(adapter_);
  }
  if (wintun_dll_) {
    FreeLibrary(wintun_dll_);
  }
  LOG_INFO("Wintun tunnel closed");
}

bool TunnelIO::LoadWintun() {
  wintun_dll_ = LoadLibraryW(L"wintun.dll");
  if (!wintun_dll_)
    return false;

  CreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(
      wintun_dll_, "WintunCreateAdapter");
  OpenAdapter = (WINTUN_OPEN_ADAPTER_FUNC)GetProcAddress(wintun_dll_,
                                                         "WintunOpenAdapter");
  CloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC)GetProcAddress(
      wintun_dll_, "WintunCloseAdapter");
  // Привязываем к правильной переменной, объявленной в заголовочном файле
  GetAdapterLuidFunc = (WINTUN_GET_ADAPTER_LUID_FUNC)GetProcAddress(
      wintun_dll_, "WintunGetAdapterLuid");
  StartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(
      wintun_dll_, "WintunStartSession");
  EndSession =
      (WINTUN_END_SESSION_FUNC)GetProcAddress(wintun_dll_, "WintunEndSession");
  GetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC)GetProcAddress(
      wintun_dll_, "WintunGetReadWaitEvent");
  ReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(
      wintun_dll_, "WintunReceivePacket");
  ReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC)GetProcAddress(
      wintun_dll_, "WintunReleaseReceivePacket");
  AllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC)GetProcAddress(
      wintun_dll_, "WintunAllocateSendPacket");
  SendPacket =
      (WINTUN_SEND_PACKET_FUNC)GetProcAddress(wintun_dll_, "WintunSendPacket");

  return CreateAdapter && OpenAdapter && CloseAdapter && GetAdapterLuidFunc &&
         StartSession && EndSession && GetReadWaitEvent && ReceivePacket &&
         ReleaseReceivePacket && AllocateSendPacket && SendPacket;
}

bool TunnelIO::ConfigureInterface(const std::string &ip_str,
                                  const std::string &mask_str) {
  IN_ADDR ip_addr, mask_addr;
  if (inet_pton(AF_INET, ip_str.c_str(), &ip_addr) != 1 ||
      inet_pton(AF_INET, mask_str.c_str(), &mask_addr) != 1) {
    LOG_ERROR("Malformed TUN configuration IP/mask values");
    return false;
  }

  // Set IP address via IP Helper
  MIB_UNICASTIPADDRESS_ROW row;
  InitializeUnicastIpAddressEntry(&row);
  row.InterfaceLuid = luid_;
  row.Address.Ipv4.sin_family = AF_INET;
  row.Address.Ipv4.sin_addr = ip_addr;

  // Convert mask to prefix length
  uint32_t mask_val = ntohl(mask_addr.S_un.S_addr);
  ULONG prefix_len = 0;
  while (mask_val) {
    prefix_len += (mask_val & 1);
    mask_val >>= 1;
  }
  row.OnLinkPrefixLength = (BYTE)prefix_len;
  row.DadState = IpDadStatePreferred;

  // [ИСПРАВЛЕНО] Убираем row.InterfaceMetric - в новых SDK его нет в
  // MIB_UNICASTIPADDRESS_ROW Вместо этого устанавливаем метрику через
  // MIB_IPINTERFACE_ROW после создания адреса

  DWORD err = CreateUnicastIpAddressEntry(&row);
  if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
    LOG_ERROR2("Failed to configure Wintun IP address, IP Helper error",
               std::to_string(err));
    return false;
  }

  // [ИСПРАВЛЕНО] Устанавливаем высокую метрику интерфейса через
  // GetIpInterfaceEntry/SetIpInterfaceEntry
  MIB_IPINTERFACE_ROW ipIfRow = {};
  ipIfRow.Family = AF_INET;
  ipIfRow.InterfaceLuid = luid_;

  if (GetIpInterfaceEntry(&ipIfRow) == NO_ERROR) {
    ipIfRow.Metric = 9999;
    SetIpInterfaceEntry(&ipIfRow);
  }

  // Set interface status to UP using legacy IP Helper API.
  // Примечание: SetIfEntry2 для MIB_IF_ROW2 не существует в IP Helper API
  // (есть только GetIfEntry2), поэтому используем старую пару
  // GetIfEntry/SetIfEntry на MIB_IFROW, адресуя интерфейс по index_ (уже
  // посчитан выше через ConvertInterfaceLuidToIndex).
  MIB_IFROW ifRow;
  ZeroMemory(&ifRow, sizeof(ifRow));
  ifRow.dwIndex = index_;

  if (GetIfEntry(&ifRow) == NO_ERROR) {
    ifRow.dwAdminStatus = MIB_IF_ADMIN_STATUS_UP;
    DWORD setErr = SetIfEntry(&ifRow);
    if (setErr != NO_ERROR) {
      LOG_ERROR2("Failed to set interface admin status, error",
                 std::to_string(setErr));
    }
  } else {
    LOG_ERROR("Failed to get interface entry for admin status update");
  }

  return true;
}

std::optional<TunnelIO::Packet> TunnelIO::Receive(uint32_t timeout_ms) {
  if (!session_)
    return std::nullopt;

  uint32_t size = 0;
  uint8_t *ptr = ReceivePacket(session_, &size);
  if (ptr) {
    return Packet{ptr, size};
  }

  // If packet ring buffer empty, wait for wait-event
  DWORD wait = WaitForSingleObject(read_event_, timeout_ms);
  if (wait == WAIT_OBJECT_0) {
    ptr = ReceivePacket(session_, &size);
    if (ptr) {
      return Packet{ptr, size};
    }
  }

  return std::nullopt;
}

void TunnelIO::Release(const Packet &packet) {
  if (session_ && packet.data) {
    ReleaseReceivePacket(session_, packet.data);
  }
}

bool TunnelIO::Send(const uint8_t *data, uint32_t len) {
  if (!session_ || !data || len == 0)
    return false;

  // Allocate memory in Wintun's ring buffer
  uint8_t *ptr = AllocateSendPacket(session_, len);
  if (!ptr) {
    LOG_ERROR("Failed to allocate send packet in Wintun ring buffer");
    return false;
  }

  // Copy packet contents
  std::memcpy(ptr, data, len);

  // Enqueue packet for the operating system to receive
  SendPacket(session_, ptr);
  return true;
}