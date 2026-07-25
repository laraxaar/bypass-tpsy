/**
 * inject_io.h — WinDivert raw packet injection wrapper.
 *
 * WHY THIS EXISTS:
 * Wintun is a virtual interface, so raw modified packets (like those with TTL=1
 * or split TCP sequences) cannot be sent directly out of it. We must inject them
 * into the real physical interface.
 * If we don't specify the correct physical interface index (IfIdx), Windows will
 * lookup the route table and send the packet back to Wintun, creating an infinite loop.
 * This class opens a send-only WinDivert handle (using filter "false") and
 * automatically discovers the real network adapter index to inject packets safely
 * to the network layer.
 */
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <string>
#include "config.h"

class InjectIO {
public:
    explicit InjectIO(const Config& cfg);
    ~InjectIO();

    // Sends a raw IPv4 packet directly to the network.
    // Automatically overrides the routing table by setting WinDivert IfIdx to the real NIC.
    bool Send(const uint8_t* packet, uint32_t len);

    // Sends a raw packet with an artificial delay (used for desync split spacing).
    bool SendDelayed(const uint8_t* packet, uint32_t len, uint32_t delay_ms);

    uint32_t GetRealInterfaceIndex() const { return real_if_idx_; }

    // Disable copy
    InjectIO(const InjectIO&) = delete;
    InjectIO& operator=(const InjectIO&) = delete;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    uint32_t real_if_idx_ = 0;
    uint32_t real_sub_if_idx_ = 0;

    void DetectRealInterface();
};
