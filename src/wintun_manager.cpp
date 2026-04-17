#include "../include/wintun_helper.h"
#include <iostream>
#include <netioapi.h>

class WintunManager {
public:
    WintunManager() : adapter(nullptr), session(nullptr) {}

    bool Initialize(const wchar_t* name) {
        if (!api.Load()) {
            std::cerr << "[-] Error: Could not load wintun.dll" << std::endl;
            return false;
        }

        GUID guid = { 0xdeadbeef, 0xdead, 0xbeef, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
        adapter = api.CreateAdapter(name, L"BypassTunnel", &guid);
        if (!adapter) {
            std::cerr << "[-] Error: Failed to create WinTun adapter" << std::endl;
            return false;
        }

        // Configure IP address using IP Helper API (simplified)
        NET_LUID luid;
        if (api.GetAdapterLuid(adapter, &luid)) {
            // Setup IP 10.0.0.1 via netsh or IP Helper would go here
            // For now, we assume the user/installer handles system-wide routing
        }

        session = api.StartSession(adapter, 0x400000);
        return session != nullptr;
    }

    void Cleanup() {
        if (session) api.EndSession(session);
        if (adapter) api.CloseAdapter(adapter);
        api.Unload();
    }

    WINTUN_SESSION_HANDLE GetSession() { return session; }
    WintunAPI& GetAPI() { return api; }

private:
    WintunAPI api;
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
};
