#include "inject_io.h"
#include "logger.h"
#include "windivert.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <thread>
#include <chrono>

#pragma comment(lib, "iphlpapi.lib")

InjectIO::InjectIO(const Config& cfg) {
    // 1. Open WinDivert send-only handle
    // Filter "false" matches no packets, making this a pure injection socket.
    // WINDIVERT_FLAG_SEND_ONLY optimizes the driver configuration.
    handle_ = WinDivertOpen("false", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SEND_ONLY);
    if (handle_ == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        throw std::runtime_error("Failed to open WinDivert handle (code " + std::to_string(err) + "). Ensure you are running as Admin.");
    }

    // 2. Discover interface to inject packets into
    int configured_idx = cfg.GetInt("inject", "real_interface_index", 0);
    if (configured_idx > 0) {
        real_if_idx_ = static_cast<uint32_t>(configured_idx);
        real_sub_if_idx_ = 0;
        LOG_INFO2("WinDivert using configured physical interface index", std::to_string(real_if_idx_));
    } else {
        DetectRealInterface();
    }
}

InjectIO::~InjectIO() {
    if (handle_ != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle_);
        LOG_INFO("WinDivert interface closed");
    }
}

void InjectIO::DetectRealInterface() {
    // Find best interface to route packets to a public destination (8.8.8.8)
    IN_ADDR dest_addr;
    inet_pton(AF_INET, "8.8.8.8", &dest_addr);

    MIB_IPFORWARD_ROW2 route_row;
    SOCKADDR_INET source_addr;
    std::memset(&route_row, 0, sizeof(route_row));
    std::memset(&source_addr, 0, sizeof(source_addr));

    SOCKADDR_INET dest_sock_addr;
    dest_sock_addr.si_family = AF_INET;
    dest_sock_addr.Ipv4.sin_addr = dest_addr;
    dest_sock_addr.Ipv4.sin_port = 0;

    DWORD err = GetBestRoute2(nullptr, 0, nullptr, &dest_sock_addr, 0, &route_row, &source_addr);
    if (err == NO_ERROR) {
        real_if_idx_ = route_row.InterfaceIndex;
        // Search sub-interface index (needed for some virtual NIC adapters)
        real_sub_if_idx_ = 0; 
        LOG_INFO2("WinDivert auto-detected physical interface index", std::to_string(real_if_idx_));
    } else {
        // Fallback interface index guess if offline or lookup fails
        real_if_idx_ = 1;
        real_sub_if_idx_ = 0;
        LOG_WARN2("WinDivert auto-detection failed, using fallback index 1. Error", std::to_string(err));
    }
}

bool InjectIO::Send(const uint8_t* packet, uint32_t len) {
    if (handle_ == INVALID_HANDLE_VALUE || !packet || len == 0) return false;

    WINDIVERT_ADDRESS addr;
    std::memset(&addr, 0, sizeof(addr));
    
    // Inject packet outbound on the physical adapter
    addr.Outbound = 1;
    addr.Network.IfIdx = real_if_idx_;
    addr.Network.SubIfIdx = real_sub_if_idx_;

    UINT write_len = 0;
    if (!WinDivertSend(handle_, packet, len, &write_len, &addr)) {
        DWORD err = GetLastError();
        LOG_ERROR2("WinDivert packet injection failed", "Error code " + std::to_string(err));
        return false;
    }

    return true;
}

bool InjectIO::SendDelayed(const uint8_t* packet, uint32_t len, uint32_t delay_ms) {
    if (delay_ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    return Send(packet, len);
}
