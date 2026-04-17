#include <iostream>
#include <vector>
#include <string>
#include "wintun_helper.h"
#include "network_util.h"

#pragma comment(lib, "ws2_32.lib")

WintunAPI wt;

// Search for SNI (Server Name Indication) in TLS Client Hello
uint8_t* FindSNI(uint8_t* payload, uint32_t size, uint32_t* sni_len) {
    if (size < 43) return nullptr; // Minimum size for Client Hello

    uint32_t pos = 43; // Skip Session ID, Ciphers, Compression
    
    // Session ID
    if (pos + 1 > size) return nullptr;
    pos += 1 + payload[pos];

    // Cipher Suites
    if (pos + 2 > size) return nullptr;
    pos += 2 + (payload[pos] << 8 | payload[pos+1]);

    // Compression
    if (pos + 1 > size) return nullptr;
    pos += 1 + payload[pos];

    // Extensions
    if (pos + 2 > size) return nullptr;
    uint32_t ext_len = (payload[pos] << 8 | payload[pos+1]);
    pos += 2;

    uint32_t end = pos + ext_len;
    if (end > size) end = size;

    while (pos + 4 <= end) {
        uint16_t type = (payload[pos] << 8 | payload[pos+1]);
        uint16_t len = (payload[pos+2] << 8 | payload[pos+3]);
        pos += 4;

        if (type == 0) { // Server Name Extension
            if (pos + 5 > end) return nullptr;
            *sni_len = (payload[pos+3] << 8 | payload[pos+4]);
            return &payload[pos+5]; // Pointer to the domain name
        }
        pos += len;
    }
    return nullptr;
}

void ProcessPacket(WINTUN_SESSION_HANDLE session, const uint8_t* data, uint32_t size) {
    if (size < sizeof(IPHeader)) return;

    IPHeader* ip = (IPHeader*)data;
    if (ip->version != 4 || ip->proto != 6) return;

    uint32_t ip_len = (ip->h_len) * 4;
    TCPHeader* tcp = (TCPHeader*)(data + ip_len);
    if (SwapBytes16(tcp->dest_port) != 443) return;

    uint32_t tcp_len = (tcp->doff) * 4;
    uint8_t* payload = (uint8_t*)(data + ip_len + tcp_len);
    uint32_t payload_size = size - ip_len - tcp_len;

    if (payload_size < sizeof(TLSRecordHeader)) return;
    TLSRecordHeader* tls = (TLSRecordHeader*)payload;

    if (tls->type == 22) { // Handshake
        uint32_t sni_len = 0;
        uint8_t* sni = FindSNI(payload + sizeof(TLSRecordHeader), payload_size - sizeof(TLSRecordHeader), &sni_len);
        
        if (sni) {
            std::string domain((char*)sni, sni_len);
            std::cout << "[!] SNI intercepted: " << domain << std::endl;
            std::cout << "[*] Applying fragmentation..." << std::endl;
            
            // TODO: Relay fragmented data through proxy_server
        }
    }
}

int main() {
    setlocale(LC_ALL, "en_US.UTF-8");

    if (!wt.Load()) {
        std::cerr << "[-] Failed to load wintun.dll! Place it next to .exe" << std::endl;
        return 1;
    }

    GUID guid = { 0xdeadbeef, 0xdead, 0xbeef, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
    WINTUN_ADAPTER_HANDLE adapter = wt.CreateAdapter(L"BypassTpsy", L"BypassTunnel", &guid);

    if (!adapter) {
        std::cerr << "[-] Failed to create adapter. Run as Administrator!" << std::endl;
        return 1;
    }

    std::cout << "[+] WinTun adapter created successfully." << std::endl;

    WINTUN_SESSION_HANDLE session = wt.StartSession(adapter, 0x400000);
    if (!session) {
        std::cerr << "[-] Failed to start session." << std::endl;
        wt.CloseAdapter(adapter);
        return 1;
    }

    std::cout << "[*] Waiting for packets... (Configure routing to direct traffic here)" << std::endl;

    HANDLE waitEvent = wt.GetReadWaitEvent(session);

    while (true) {
        uint32_t size = 0;
        uint8_t* packet = wt.ReceivePacket(session, &size);

        if (packet) {
            ProcessPacket(session, packet, size);
            wt.ReleaseReceivePacket(session, packet);
        } else {
            WaitForSingleObject(waitEvent, INFINITE);
        }
    }

    wt.EndSession(session);
    wt.CloseAdapter(adapter);
    wt.Unload();

    return 0;
}
